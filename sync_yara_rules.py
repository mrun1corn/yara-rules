import os
import subprocess
import hashlib
import json
import shutil
import re
import logging
import sys
import urllib.request
import urllib.error
import time
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────
#  Optional: YARA syntax validation
#  Install with: pip install yara-python
# ─────────────────────────────────────────────
try:
    import yara
    YARA_VALIDATION = True
except ImportError:
    YARA_VALIDATION = False

# ══════════════════════════════════════════════
#  ENVIRONMENT & CONFIGURATION
# ══════════════════════════════════════════════
def load_env(env_path=".env"):
    """Minimal .env loader to avoid extra dependencies."""
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip().strip('"').strip("'")

load_env()

REPO_FILE     = "repos.txt"
RULES_FILE    = "rules.json"
SOURCE_DIR    = "source_repos"
OUTPUT_DIR    = "Organized_YARA"
HASH_DB       = "seen_hashes.json"
MAPPING_JSON  = "yara_structure_mapping.json"
PATH_MAPPING  = "yara_path_mapping.json"
AI_CACHE_FILE = "ai_category_cache.json"
LOG_FILE      = "yara_organizer.log"

USE_AI = True

# Gemini free API — get your key at https://aistudio.google.com/app/apikey
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_URL     = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "{model}:generateContent?key={key}"
)

# ══════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)


# ══════════════════════════════════════════════
#  LOAD TAXONOMY FROM rules.json
#
#  Expected structure:
#  {
#    "defaults": { "category": "...", "subcategory": "..." },
#    "taxonomy": {
#      "<category>": {
#        "subcategories": ["Sub1", "Sub2", ...],
#        "keywords": ["kw1", "kw2", ...]
#      },
#      ...
#    }
#  }
# ══════════════════════════════════════════════
def load_rules(rules_file=RULES_FILE):
    if not os.path.exists(rules_file):
        log.error(f"'{rules_file}' not found. Create it before running.")
        sys.exit(1)

    with open(rules_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    for key in ["defaults", "taxonomy"]:
        if key not in data:
            log.error(f"'{rules_file}' is missing required key: '{key}'")
            sys.exit(1)

    taxonomy = data["taxonomy"]

    # Derive flat sets from the nested structure
    valid_categories    = set(taxonomy.keys())
    valid_subcategories = set()
    for cat_data in taxonomy.values():
        valid_subcategories.update(cat_data.get("subcategories", []))

    # Build keyword map: (keyword, category, best_subcategory)
    # best_subcategory = first entry in that category's subcategories list
    keyword_map = []
    for category, cat_data in taxonomy.items():
        subs     = cat_data.get("subcategories", [])
        keywords = cat_data.get("keywords", [])
        default_sub = subs[0] if subs else data["defaults"]["subcategory"]
        for kw in keywords:
            keyword_map.append((kw.lower(), category, default_sub))

    # Build human-readable prompt lists
    cat_lines = []
    for category, cat_data in sorted(taxonomy.items()):
        subs = ", ".join(cat_data.get("subcategories", []))
        cat_lines.append(f"  - {category}  (subcategories: {subs})")
    prompt_taxonomy = "\n".join(cat_lines)

    return {
        "taxonomy":          taxonomy,
        "valid_categories":  valid_categories,
        "valid_subcategories": valid_subcategories,
        "default_cat":       data["defaults"]["category"],
        "default_sub":       data["defaults"]["subcategory"],
        "keyword_map":       keyword_map,
        "prompt_taxonomy":   prompt_taxonomy,
    }


# Load once at startup — all functions reference these globals
RULES               = load_rules()
TAXONOMY            = RULES["taxonomy"]
VALID_CATEGORIES    = RULES["valid_categories"]
VALID_SUBCATEGORIES = RULES["valid_subcategories"]
DEFAULT_CATEGORY    = RULES["default_cat"]
DEFAULT_SUBCATEGORY = RULES["default_sub"]
KEYWORD_MAP         = RULES["keyword_map"]


# ══════════════════════════════════════════════
#  REPO LOADING
# ══════════════════════════════════════════════
def get_repos():
    if not os.path.exists(REPO_FILE):
        log.warning(f"'{REPO_FILE}' not found — no repos to sync.")
        return []
    with open(REPO_FILE, "r") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


# ══════════════════════════════════════════════
#  HASHING
# ══════════════════════════════════════════════
def get_md5(file_path):
    h = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


# ══════════════════════════════════════════════
#  YARA HEADER EXTRACTION
# ══════════════════════════════════════════════
def extract_yara_header(file_path, char_limit=3000):
    """Extracts rule names + meta fields from the top of a YARA file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(char_limit)
        rule_names  = re.findall(r"rule\s+([\w\d_]+)", content)
        meta_fields = re.findall(
            r'(?:description|author|reference|family|tags?)\s*=\s*"([^"]+)"',
            content, re.IGNORECASE
        )
        return " | ".join(rule_names + meta_fields)
    except Exception:
        return ""


# ══════════════════════════════════════════════
#  YARA SYNTAX VALIDATION
# ══════════════════════════════════════════════
def validate_yara(file_path):
    if not YARA_VALIDATION:
        return True, ""
    try:
        yara.compile(filepath=str(file_path))
        return True, ""
    except yara.SyntaxError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


# ══════════════════════════════════════════════
#  GEMINI API CALL  (pure stdlib — no SDK)
# ══════════════════════════════════════════════
def call_gemini(prompt):
    url = GEMINI_URL.format(model=GEMINI_MODEL, key=GEMINI_API_KEY)
    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature":     0.1,
            "maxOutputTokens": 150,
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    return data["candidates"][0]["content"]["parts"][0]["text"].strip()


# ══════════════════════════════════════════════
#  AI CATEGORIZATION (Batch)
# ══════════════════════════════════════════════
def batch_ai_categorize(headers_to_classify, cache):
    """
    Classifies YARA rules in batches of 20 to optimize API usage and speed.
    """
    results = {}
    
    # 1. Filter out already cached items
    to_process = []
    for item_id, header in headers_to_classify:
        cache_key = hashlib.md5(header.encode()).hexdigest()
        if cache_key in cache:
            results[item_id] = cache[cache_key]
        else:
            to_process.append((item_id, header, cache_key))
            
    if not to_process:
        return results

    log.info(f"  Sending {len(to_process)} rules to Gemini in batches...")
    
    # 2. Process in batches of 20
    batch_size = 20
    for i in range(0, len(to_process), batch_size):
        batch = to_process[i:i + batch_size]
        
        items_json = []
        for idx, (item_id, header, _) in enumerate(batch):
            items_json.append({"id": idx, "header": header})

        prompt = f"""You are a cybersecurity expert specializing in YARA rule classification.
Classify each of the {len(batch)} YARA rule headers provided below into a category and subcategory from the allowed taxonomy.

--- Taxonomy (category -> allowed subcategories) ---
{RULES['prompt_taxonomy']}

--- Rules to Classify ---
{json.dumps(items_json, indent=2)}

--- Classification Guide ---
- Keylogger rules             -> spyware -> Keyloggers
- PowerShell attacks           -> scripting_attacks -> PowerShell_Abuse
- Banking trojans              -> trojans -> Banking_Trojans
- AMSI / AV bypass             -> security -> AMSI_Bypass
- File-encrypting ransomware   -> ransomware -> Crypto_Ransomware
- Rootkit / kernel drivers     -> rootkit -> Rootkits_Kernel
- SQL injection patterns        -> sql_injection -> SQL_Brute_Force
- Phishing documents / lures   -> phishing -> Phishing_Lures
- Office macros / VBA           -> malware -> Macros
- Shellcode / process injection -> scripting_attacks -> Shellcode
- Coin / crypto miners          -> malware -> CoinMiner
- Sandbox / VM evasion          -> behavioral -> Evasion_Sandbox
- Droppers / loaders            -> malware -> Downloaders_Droppers
- RATs / remote access          -> trojans -> RATs
- Credential dumping            -> credential_theft -> Infostealers
- Persistence / autorun         -> autorun -> Persistence_Methods
- If uncertain                  -> {DEFAULT_CATEGORY} -> {DEFAULT_SUBCATEGORY}

Respond ONLY with a JSON array of objects.
[{{ "id": 0, "category": "category_name", "subcategory": "subcategory_name" }}, ...]"""

        try:
            raw = call_gemini(prompt)
            raw = re.sub(r"```[a-z]*", "", raw).strip("` \n")
            
            # Find the JSON array in the response
            array_match = re.search(r'\[.*\]', raw, re.DOTALL)
            if not array_match:
                raise ValueError("No JSON array found in Gemini response.")
            
            batch_results = json.loads(array_match.group())
            
            # Map results back to items
            for res in batch_results:
                b_idx = res.get("id")
                if b_idx is not None and b_idx < len(batch):
                    item_id, _, cache_key = batch[b_idx]
                    category = res.get("category", DEFAULT_CATEGORY)
                    subcategory = res.get("subcategory", DEFAULT_SUBCATEGORY)
                    
                    # Validate against taxonomy
                    if category not in VALID_CATEGORIES:
                        category = DEFAULT_CATEGORY
                    allowed_subs = set(TAXONOMY[category].get("subcategories", []))
                    if subcategory not in allowed_subs:
                        subcategory = TAXONOMY[category]["subcategories"][0] if allowed_subs else DEFAULT_SUBCATEGORY
                    
                    res_obj = {"category": category, "subcategory": subcategory}
                    results[item_id] = res_obj
                    cache[cache_key] = res_obj
                    
            # Rate limiting for Free Tier (15 RPM)
            if i + batch_size < len(to_process):
                log.info("  Waiting for RPM limit safety (4s)...")
                time.sleep(4)

        except Exception as e:
            log.warning(f"  Batch AI failed: {e}. Items will use keyword fallback.")
            # Remaining items in this batch will be missing from 'results' and fallback later

    return results


# ══════════════════════════════════════════════
#  FALLBACK: KEYWORD CATEGORIZATION (Weighted)
# ══════════════════════════════════════════════
def keyword_categorize(file_path, repo_root):
    header   = extract_yara_header(file_path)
    path_str = str(file_path).lower()
    signal   = f"{path_str} {header.lower()}"

    best_cat, best_sub = DEFAULT_CATEGORY, DEFAULT_SUBCATEGORY
    max_weight = -1

    # Weights: Specificity increases weight
    for keyword, category, subcategory in KEYWORD_MAP:
        weight = len(keyword) # Simple weight: longer keywords are usually more specific
        if keyword in signal:
            if weight > max_weight:
                max_weight = weight
                best_cat, best_sub = category, subcategory

    return best_cat, best_sub


# ══════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════
def main():
    start_time = datetime.now()
    ai_ready   = USE_AI and bool(GEMINI_API_KEY)

    log.info("═" * 60)
    log.info("YARA Organizer (Optimized)")
    log.info(f"  Rules file   : {RULES_FILE}")
    log.info(f"  AI engine    : {'Gemini (Batch Mode)' if ai_ready else 'OFF'}")
    log.info("═" * 60)

    # Load databases
    seen_hashes = {}
    if os.path.exists(HASH_DB):
        with open(HASH_DB) as f: seen_hashes = json.load(f)
    path_mapping = {}
    if os.path.exists(PATH_MAPPING):
        with open(PATH_MAPPING) as f: path_mapping = json.load(f)
    ai_cache = {}
    if os.path.exists(AI_CACHE_FILE):
        with open(AI_CACHE_FILE) as f: ai_cache = json.load(f)

    # Step 1: Sync repos
    repo_info = sync_repos()
    if not repo_info: return

    # Step 2: Discovery Pass (Find what's new/changed)
    stats = dict(processed=0, updated=0, skipped_dup=0, skipped_invalid=0,
                 errors=0, ai_calls=0, kw_fallback=0, deleted=0)
    
    seen_in_this_run = set()
    to_classify = [] # List of (id, header, file_path, file_hash, repo_key)
    item_id_counter = 0

    log.info("Discovery Pass: Analyzing source repositories...")
    for repo_name, repo_root in repo_info:
        for root, _, files in os.walk(repo_root):
            for filename in files:
                if not (filename.endswith(".yar") or filename.endswith(".yara")): continue
                
                file_path = Path(root) / filename
                repo_key = str(file_path.relative_to(SOURCE_DIR)).replace("\\", "/")
                seen_in_this_run.add(repo_key)

                try:
                    file_hash = get_md5(file_path)

                    # Check for updates or duplicate source paths
                    if repo_key in path_mapping:
                        old_info = path_mapping[repo_key]
                        if old_info.get("md5") == file_hash:
                            if Path(old_info.get("organized_path", "")).exists():
                                stats["skipped_dup"] += 1
                                continue
                        else:
                            # Content changed - clean up old organized file
                            old_dest = Path(old_info.get("organized_path", ""))
                            is_shared = any(k != repo_key and v.get("organized_path") == old_info.get("organized_path") for k, v in path_mapping.items())
                            if old_dest.exists() and not is_shared:
                                old_dest.unlink()
                            if old_info.get("md5") in seen_hashes and not is_shared:
                                del seen_hashes[old_info["md5"]]

                    # Check global deduplication
                    if file_hash in seen_hashes and Path(seen_hashes[file_hash]).exists():
                        path_mapping[repo_key] = {"md5": file_hash, "organized_path": seen_hashes[file_hash]}
                        stats["skipped_dup"] += 1
                        continue

                    # New rule discovery
                    is_valid, _ = validate_yara(file_path)
                    if not is_valid:
                        stats["skipped_invalid"] += 1
                        continue

                    header = extract_yara_header(file_path)
                    to_classify.append((item_id_counter, header, file_path, file_hash, repo_key))
                    item_id_counter += 1

                except Exception as e:
                    log.error(f"Error during discovery of {file_path}: {e}")
                    stats["errors"] += 1

    # Step 3: Categorization Pass (Batch AI)
    log.info(f"Categorization Pass: Classifying {len(to_classify)} rules...")
    ai_results = {}
    if ai_ready and to_classify:
        headers_only = [(item[0], item[1]) for item in to_classify if item[1]]
        ai_results = batch_ai_categorize(headers_only, ai_cache)
        stats["ai_calls"] = len(ai_results)

    # Step 4: Organization Pass (Final Copy)
    log.info("Organization Pass: Sorting files...")
    for item_id, header, file_path, file_hash, repo_key in to_classify:
        try:
            res = ai_results.get(item_id)
            if not res:
                category, subcategory = keyword_categorize(file_path, SOURCE_DIR)
                stats["kw_fallback"] += 1
            else:
                category, subcategory = res["category"], res["subcategory"]

            dest = safe_copy(file_path, Path(OUTPUT_DIR) / category / subcategory, file_hash)
            dest_posix = dest.as_posix()
            seen_hashes[file_hash] = dest_posix
            path_mapping[repo_key] = {"md5": file_hash, "organized_path": dest_posix}
            stats["processed"] += 1
        except Exception as e:
            log.error(f"Error organizing {file_path}: {e}")
            stats["errors"] += 1

    # Step 5: Deletion Pass
    log.info("Deletion Pass: Cleaning up removed rules...")
    for repo_key in list(path_mapping.keys()):
        if repo_key not in seen_in_this_run:
            info = path_mapping[repo_key]
            old_dest = Path(info.get("organized_path", ""))
            is_still_needed = any(k != repo_key and k in seen_in_this_run and v.get("organized_path") == info.get("organized_path") for k, v in path_mapping.items())
            if old_dest.exists() and not is_still_needed:
                old_dest.unlink()
                if info.get("md5") in seen_hashes: del seen_hashes[info["md5"]]
            del path_mapping[repo_key]
            stats["deleted"] += 1

    purge_unknown_folders()

    # Save State
    with open(HASH_DB, "w") as f: json.dump(seen_hashes, f, indent=4)
    with open(PATH_MAPPING, "w") as f: json.dump(path_mapping, f, indent=4)
    with open(AI_CACHE_FILE, "w") as f: json.dump(ai_cache, f, indent=4)
    with open(MAPPING_JSON, "w") as f: json.dump(build_mapping(), f, indent=4)

    elapsed = (datetime.now() - start_time).total_seconds()
    log.info("═" * 60)
    log.info(f"Finished in {elapsed:.1f}s")
    log.info(f"  Rules processed    : {stats['processed']}")
    log.info(f"  Rules deleted      : {stats['deleted']}")
    log.info(f"  Duplicates skipped : {stats['skipped_dup']}")
    log.info(f"  AI categorization  : {stats['ai_calls']}")
    log.info(f"  Keyword fallback   : {stats['kw_fallback']}")
    log.info("═" * 60)


if __name__ == "__main__":
    main()