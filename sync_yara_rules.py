import os
import subprocess
import hashlib
import json
import shutil
from pathlib import Path

# --- Configuration ---
REPO_FILE = "repos.txt"
CATEGORY_FILE = "catagory.txt"
SUB_CATEGORY_FILE = "sub_catagory.txt"
SOURCE_DIR = "source_repos"
OUTPUT_DIR = "Organized_YARA"
HASH_DB = "seen_hashes.json"
MAPPING_JSON = "yara_structure_mapping.json"

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

    found_cat = "malware"
    found_sub = "General"

    # 1. Try technical sub-categories first (most specific)
    for sub in SUB_CATEGORIES:
        if sub.lower() in signal:
            found_sub = sub
            break
            
    # 2. Identify main category
    # Priority mapping: Rule Header > Meta Description > Path
    if "ransom" in signal: found_cat = "ransomware"
    elif "trojan" in signal: found_cat = "trojans"
    elif "spyware" in signal or "stealer" in signal: found_cat = "spyware"
    elif "worm" in signal: found_cat = "worms"
    elif "rootkit" in signal: found_cat = "rootkit"
    elif "phish" in signal: found_cat = "phishing"
    elif "exploit" in signal or "cve" in signal: found_cat = "scripting_attacks"
    elif "brute" in signal: found_cat = "brute_force"
    elif "bypass" in signal: found_cat = "security"
    else:
        # Fallback to original path-based discovery if keywords fail
        path_parts = file_path.relative_to(repo_root).parts
        if len(path_parts) >= 2:
            found_cat = path_parts[0].lower()
            
    # Clean up names
    # Remove symbols like #, @, !, etc.
    found_cat = re.sub(r"[^a-zA-Z0-9_]", "", found_cat.replace(" ", "_").replace("-", "_")).lower()
    found_sub = re.sub(r"[^a-zA-Z0-9_]", "", found_sub.replace(" ", "_").replace("-", "_"))

    # Mapping common abbreviations to cleaner names
    clean_map = {
        "pua": "potentially_unwanted_apps",
        "apt": "advanced_persistent_threats"
    }
    found_cat = clean_map.get(found_cat, found_cat)
    
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

    repo_info = sync_repos()
    
    new_files_count = 0
    print("Processing YARA rules...")
    
    for repo_name, repo_root in repo_info:
        for root, _, files in os.walk(repo_root):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    file_path = Path(root) / file
                    try:
                        file_hash = get_md5(file_path)
                        
                        # Fix: Standardize path to forward slashes for the DB
                        if file_hash in seen_hashes:
                            existing_path = Path(seen_hashes[file_hash])
                            if existing_path.exists():
                                continue 
                        
                        cat, sub = get_category_info(file_path, repo_root)
                        target_dir = Path(OUTPUT_DIR) / cat / sub
                        target_dir.mkdir(parents=True, exist_ok=True)
                        
                        target_file = target_dir / file
                        
                        # Handle name collisions
                        if target_file.exists():
                            # If it's the same hash already at this exact location, skip
                            if get_md5(target_file) == file_hash:
                                seen_hashes[file_hash] = target_file.as_posix()
                                continue
                            target_file = target_dir / f"{target_file.stem}_{file_hash[:8]}{target_file.suffix}"

                        shutil.copy2(file_path, target_file)
                        new_files_count += 1
                        # Always store as POSIX (forward slashes) in JSON
                        seen_hashes[file_hash] = target_file.as_posix()
                            
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")

    # Save hash database
    with open(HASH_DB, "w") as f:
        json.dump(seen_hashes, f, indent=4)

    # Rebuild mapping JSON based on current Organized_YARA content
    print("Updating mapping index...")
    final_structure = {}
    for cat_dir in Path(OUTPUT_DIR).iterdir():
        if cat_dir.is_dir():
            cat_name = cat_dir.name
            final_structure[cat_name] = {}
            for sub_dir in cat_dir.iterdir():
                if sub_dir.is_dir():
                    sub_name = sub_dir.name
                    files = [f.name for f in sub_dir.glob("*.yar*")]
                    final_structure[cat_name][sub_name] = sorted(files)

    with open(MAPPING_JSON, "w") as f:
        json.dump(final_structure, f, indent=4)

    print(f"Sync complete. Added {new_files_count} new unique rules.")
    print(f"Total unique rules: {len(seen_hashes)}")

if __name__ == "__main__":
    main()
