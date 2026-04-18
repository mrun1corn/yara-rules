import os
import hashlib
import json
from pathlib import Path

OUTPUT_DIR = "Organized_YARA"
HASH_DB = "seen_hashes.json"

def get_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def init():
    seen_hashes = {}
    print("Initializing hash database from existing rules...")
    for root, _, files in os.walk(OUTPUT_DIR):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                file_path = Path(root) / file
                file_hash = get_md5(file_path)
                # Store using POSIX forward slashes
                seen_hashes[file_hash] = file_path.as_posix()
    
    with open(HASH_DB, "w") as f:
        json.dump(seen_hashes, f, indent=4)
    print(f"Initialized with {len(seen_hashes)} unique rules.")

if __name__ == "__main__":
    init()
