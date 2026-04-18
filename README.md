# YARA Rules Management System

A fully automated system to collect, deduplicate, and organize YARA rules from multiple high-quality open-source intelligence (OSINT) repositories.

## 🚀 How It Works

This system uses a Python-based automation engine (`sync_yara_rules.py`) to keep your rule collection fresh and organized.

### 1. Synchronization
The script reads target repository URLs from `repos.txt`, clones or pulls them into a temporary `source_repos/` directory, and scans them for `.yar` and `.yara` files.

### 2. Intelligent Deduplication
To prevent your collection from being cluttered with redundant rules:
*   **Hash Validation**: Every file is processed using the **MD5 algorithm**.
*   **Database Tracking**: The system maintains `seen_hashes.json`. If a rule's content already exists anywhere in your collection, it is skipped, even if it has a different filename or comes from a different repo.
*   **Collision Safety**: If two *different* rules share the same filename, the system appends a unique 8-character hash to the filename to ensure both are preserved.

### 3. Dynamic Categorization
The system organizes rules into a `Category/Sub-category/File` structure inside the `Organized_YARA/` folder using a three-tier logic:
*   **Path Discovery**: It attempts to extract categories directly from the folder structure of the source repository.
*   **Keyword Matching**: If the path is ambiguous, it scans for predefined keywords (e.g., `ransomware`, `trojans`, `rootkit`).
*   **Automatic Foldering**: If a new category is discovered in a source repo that isn't in our list, the system **automatically creates a new folder** for it.
*   **Defaulting**: Rules that cannot be identified are placed in `malware/General`.

## 🛠 Maintenance Tasks

### Adding New Sources
To add a new YARA repository:
1.  Open `repos.txt`.
2.  Paste the GitHub URL on a new line.
3.  Run the update (locally or via GitHub Actions).

### Running Updates
*   **Manually (Local)**: Run `python sync_yara_rules.py`.
*   **On GitHub**: Go to the **Actions** tab, select **Update YARA Rules**, and click **Run workflow**.

## 📂 Project Structure
*   `Organized_YARA/`: The final, clean collection of unique rules.
*   `yara_structure_mapping.json`: A generated index mapping every category to its files.
*   `repos.txt`: The list of source repositories.
*   `seen_hashes.json`: The "memory" of the system used for deduplication.
*   `sync_yara_rules.py`: The core automation logic.
