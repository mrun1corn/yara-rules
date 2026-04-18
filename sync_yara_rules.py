import os
import subprocess
import hashlib
import json
import shutil
from pathlib import Path

# --- Configuration ---
REPO_FILE = "repos.txt"
SOURCE_DIR = "source_repos"
OUTPUT_DIR = "Organized_YARA"
HASH_DB = "seen_hashes.json"
MAPPING_JSON = "yara_structure_mapping.json"

def get_repos():
    if not os.path.exists(REPO_FILE):
        return []
    with open(REPO_FILE, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

CATEGORIES = [
    'sql_injection', 'scripting_attacks', 'brute_force', 'credential_theft', 
    'phishing', 'behavioral', 'rootkit', 'malware', 'trojans', 
    'ransomware', 'spyware', 'worms', 'autorun', 'security'
]

SUB_CATEGORIES = [
    'AMSI_Bypass', 'Banking_Trojans', 'Crypto_Ransomware', 'Downloaders_Droppers', 
    'Evasion_Sandbox', 'Infostealers', 'Injection_Techniques', 'Keyloggers', 
    'Persistence_Methods', 'Phishing_Lures', 'PowerShell_Abuse', 'RATs', 
    'Rootkits_Kernel', 'SQL_Brute_Force'
]

def get_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_category_info(file_path, repo_root):
    """
    Dynamically identifies category and sub-category based on the file's path 
    relative to the repository root.
    """
    path_parts = file_path.relative_to(repo_root).parts
    filename = file_path.name.lower()
    
    # Defaults
    found_cat = "malware"
    found_sub = "General"

    # Strategy 1: Use the folder structure of the source repo
    # If the file is in repo/category/subcat/file.yar
    if len(path_parts) >= 3:
        found_cat = path_parts[0].lower()
        found_sub = path_parts[1]
    # If the file is in repo/category/file.yar
    elif len(path_parts) == 2:
        found_cat = path_parts[0].lower()
        
    # Strategy 2: Refine using keywords if we are still at 'malware' default
    if found_cat == "malware":
        for cat in CATEGORIES:
            if cat in str(file_path).lower() or filename.startswith(cat + "_"):
                found_cat = cat
                break

    for sub in SUB_CATEGORIES:
        if sub.lower() in str(file_path).lower():
            found_sub = sub
            break
            
    # Clean up names (remove underscores, etc. if desired, or keep as is)
    found_cat = found_cat.replace(" ", "_").replace("-", "_")
    
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
