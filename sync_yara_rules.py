import os
import subprocess
import hashlib
import json
import shutil
import re
from pathlib import Path

# --- Configuration ---
REPO_FILE = "repos.txt"
CATEGORY_FILE = "catagory.txt"
SUB_CATEGORY_FILE = "sub_catagory.txt"
SOURCE_DIR = "source_repos"
OUTPUT_DIR = "Organized_YARA"
HASH_DB = "seen_hashes.json"
MAPPING_JSON = "yara_structure_mapping.json"
PATH_MAPPING_JSON = "yara_path_mapping.json"
ALL_RULES_CSV = "all_rules.csv"
ALL_PATHS_TXT = "all_yara_paths.txt"

def get_repos():
    if not os.path.exists(REPO_FILE):
        return []
    with open(REPO_FILE, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def get_authorized_categories():
    if not os.path.exists(CATEGORY_FILE):
        return ['malware']
    cats = []
    with open(CATEGORY_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("http"):
                continue
            # Extract just the category name before any notes like (monitor...)
            cat_name = re.split(r"[\s\(]", line)[0].lower()
            if cat_name:
                cats.append(cat_name)
    return list(set(cats))

def get_authorized_sub_categories():
    if not os.path.exists(SUB_CATEGORY_FILE):
        return []
    subs = []
    with open(SUB_CATEGORY_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                subs.append(line)
    return subs

CATEGORIES = get_authorized_categories()
SUB_CATEGORIES = get_authorized_sub_categories()

def get_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

import re

def get_content_info(file_path):
    """
    Reads the YARA file to extract the rule name and meta description.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(2000) # Read the first 2000 chars (usually enough for header/meta)
            
            # Extract rule name(s)
            rule_names = re.findall(r"rule\s+([\w\d_]+)", content)
            # Extract description from meta
            meta_desc = re.search(r"description\s*=\s*\"([^\"]+)\"", content)
            
            combined_info = " ".join(rule_names).lower()
            if meta_desc:
                combined_info += " " + meta_desc.group(1).lower()
            
            return combined_info
    except:
        return ""

def get_category_info(file_path, repo_root):
    path_str = str(file_path).lower()
    filename = file_path.name.lower()
    content_info = get_content_info(file_path)
    
    # Combined signal for better detection
    signal = f"{path_str} {filename} {content_info}"

    found_cat = None
    found_sub = "General"

    # 1. Try technical sub-categories first (most specific)
    for sub in SUB_CATEGORIES:
        if sub.lower() in signal:
            found_sub = sub
            break
            
    # 2. Strict Category Mapping (Mapping everything to your 14 authorized buckets)
    if "ransom" in signal: found_cat = "ransomware"
    elif "trojan" in signal: found_cat = "trojans"
    elif "spyware" in signal or "stealer" in signal: found_cat = "spyware"
    elif "worm" in signal: found_cat = "worms"
    elif "rootkit" in signal: found_cat = "rootkit"
    elif "phish" in signal: found_cat = "phishing"
    elif "exploit" in signal or "cve" in signal: found_cat = "scripting_attacks"
    elif "brute" in signal: found_cat = "brute_force"
    elif "bypass" in signal: found_cat = "security"
    elif "autorun" in signal: found_cat = "autorun"
    elif "sql" in signal or "inject" in signal: found_cat = "sql_injection"
    elif "behavi" in signal or "evas" in signal: found_cat = "behavioral"
    elif "credential" in signal: found_cat = "credential_theft"
    
    # 3. Fallback to path-based but ONLY if it matches an authorized category
    if not found_cat:
        path_parts = file_path.relative_to(repo_root).parts
        for part in path_parts:
            part_clean = re.sub(r"[^a-zA-Z0-9_]", "", part.lower())
            if part_clean in CATEGORIES:
                found_cat = part_clean
                break

    # 4. Final bucket: Everything else goes to 'malware'
    if not found_cat or found_cat not in CATEGORIES:
        found_cat = "malware"
            
    return found_cat, found_sub

def sync_repos():
    if not os.path.exists(SOURCE_DIR):
        os.makedirs(SOURCE_DIR)
    
    repos = get_repos()
    sync_results = []
    for repo_url in repos:
        repo_name = repo_url.split("/")[-1]
        target_path = os.path.join(SOURCE_DIR, repo_name)
        
        if os.path.exists(target_path):
            print(f"Updating {repo_name}...")
            subprocess.run(["git", "-C", target_path, "pull"], capture_output=True)
        else:
            print(f"Cloning {repo_name}...")
            subprocess.run(["git", "clone", "--depth", "1", repo_url, target_path], capture_output=True)
        sync_results.append((repo_name, Path(target_path)))
    return sync_results

def main():
    # Load seen hashes
    seen_hashes = {}
    if os.path.exists(HASH_DB):
        with open(HASH_DB, "r") as f:
            seen_hashes = json.load(f)

    # STEP 1: Sync all repos first
    repo_info = sync_repos()
    
    # STEP 2: Process rules
    new_files_count = 0
    print("Processing YARA rules...")
    for repo_name, repo_root in repo_info:
        for root, _, files in os.walk(repo_root):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    file_path = Path(root) / file
                    try:
                        file_hash = get_md5(file_path)
                        if file_hash in seen_hashes and Path(seen_hashes[file_hash]).exists():
                            continue 
                        
                        cat, sub = get_category_info(file_path, repo_root)
                        target_dir = Path(OUTPUT_DIR) / cat / sub
                        target_dir.mkdir(parents=True, exist_ok=True)
                        
                        target_file = target_dir / file
                        if target_file.exists():
                            if get_md5(target_file) == file_hash:
                                continue
                            target_file = target_dir / f"{target_file.stem}_{file_hash[:8]}{target_file.suffix}"

                        shutil.copy2(file_path, target_file)
                        new_files_count += 1
                        seen_hashes[file_hash] = target_file.as_posix()
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")

    # STEP 3: Cleanup unauthorized folders (Purge)
    print("Cleaning up unauthorized category folders...")
    if os.path.exists(OUTPUT_DIR):
        for item in os.listdir(OUTPUT_DIR):
            item_path = os.path.join(OUTPUT_DIR, item)
            if os.path.isdir(item_path) and item.lower() not in CATEGORIES:
                print(f"Removing unauthorized category: {item}")
                shutil.rmtree(item_path)

    # STEP 4: Save database and mapping
    with open(HASH_DB, "w") as f:
        json.dump(seen_hashes, f, indent=4)

    print("Updating mapping indexes...")
    final_structure = {}
    path_structure = {}
    for cat_dir in sorted(Path(OUTPUT_DIR).iterdir()):
        if cat_dir.is_dir() and cat_dir.name in CATEGORIES:
            cat_name = cat_dir.name
            final_structure[cat_name] = {}
            path_structure[cat_name] = {}
            for sub_dir in sorted(cat_dir.iterdir()):
                if sub_dir.is_dir():
                    sub_name = sub_dir.name
                    files = sorted(list(sub_dir.glob("*.yar*")))
                    if files:
                        final_structure[cat_name][sub_name] = [f.name for f in files]
                        path_structure[cat_name][sub_name] = [f.as_posix() for f in files]

    with open(MAPPING_JSON, "w") as f:
        json.dump(final_structure, f, indent=4)
    with open(PATH_MAPPING_JSON, "w") as f:
        json.dump(path_structure, f, indent=4)

    # STEP 5: Generate Path Indexes
    print("Generating path indexes...")
    with open(ALL_RULES_CSV, "w") as csv_f, open(ALL_PATHS_TXT, "w") as txt_f:
        csv_f.write('"Name","Length","FullName"\n')
        for root, _, files in os.walk(OUTPUT_DIR):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    file_path = Path(root) / file
                    size = file_path.stat().st_size
                    # Write to CSV
                    csv_f.write(f'"{file}","{size}","{file_path.absolute().as_posix()}"\n')
                    # Write to TXT
                    txt_f.write(f"{file_path.absolute().as_posix()}\n")

    print(f"Sync complete. Added {new_files_count} new unique rules.")

if __name__ == "__main__":
    main()
