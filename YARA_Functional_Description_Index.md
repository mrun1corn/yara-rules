# Comprehensive YARA Category Functional Index

This document provides a detailed technical breakdown of each YARA category within the `selected_rules` repository. It explains the specific threats, behaviors, and technical indicators each group of rules is designed to detect.

---

## 1. SQL Injection & Database Attacks (`sql_injection`)
**Technical Purpose:** To detect exploitation attempts and post-compromise activities targeting SQL-based database engines (MSSQL, MySQL, SQLite, PostgreSQL).

*   **Detection Capabilities:**
    *   **Syntax Injection:** Detects common SQL injection patterns (e.g., `UNION SELECT`, `OR 1=1`, `xp_cmdshell`) inside web requests or log files.
    *   **Process Hijacking:** Identifies malware that attempts to inject code into legitimate SQL server processes (e.g., `sqlservr.exe`).
    *   **SQL Brute Force:** Targets tools that automate credential guessing against database ports (default 1433, 3306).
    *   **Credential Dumping:** Identifies scripts like `Zapchast` or `SqliteStealer` that extract saved passwords from local browser or application databases.

---

## 2. Scripting Attacks (`scripting_attacks`)
**Technical Purpose:** Targets malicious code written in scripting languages, often used as "stage-0" downloaders or for lateral movement.

*   **Detection Capabilities:**
    *   **PowerShell Abuse:** Detects obfuscated commands (`Base64`, `IEX`, `Enc`), bypasses for Execution Policy, and AMSI-tampering scripts.
    *   **Windows Script Host:** Targets malicious VBScript and JScript (often delivered via .zip or .hta files).
    *   **Linux/Android Shell Scripts:** Identifies malicious `.sh` scripts used for botnet propagation or device rooting.
    *   **Macro Payloads:** Detects VBA macros in Office documents that trigger shell execution.

---

## 3. Brute Force Attacks (`brute_force`)
**Technical Purpose:** Identifies tools and patterns associated with automated, exhaustive credential guessing.

*   **Detection Capabilities:**
    *   **HackTool Detection:** Rules for known brute-force kits like `Dubrute`, `Hydra`, and `Ncrack`.
    *   **Protocol Targeting:** Detects scripts specifically designed for RDP, SSH, FTP, and Telnet cracking.
    *   **Batch Automation:** Targets `.bat` and `.cmd` wrappers used to launch repeated login attempts with different wordlists.

---

## 4. Credential Theft (`credential_theft`)
**Technical Purpose:** To detect the extraction of sensitive data, including passwords, hashes, tokens, and certificates.

*   **Detection Capabilities:**
    *   **Memory Dumping:** Detects usage of `Procdump`, `Comsvcs.dll`, and `LSASS` memory access for password harvesting (Mimikatz style).
    *   **Stealer Malware:** Targets families like `AgentTesla`, `Redline`, and `LokiBot` which focus on browser, email, and FTP credential theft.
    *   **Keyloggers:** Identifies logic used to hook keyboard events and save keystrokes to hidden log files.

---

## 5. Phishing & Social Engineering (`phishing`)
**Technical Purpose:** Detects the "delivery" phase of an attack, focusing on deceptive content and malicious attachments.

*   **Detection Capabilities:**
    *   **Email Lures:** Identifies keywords associated with urgent/fake notifications (e.g., "Invoice Overdue", "Account Suspended").
    *   **Template Injection:** Detects Office documents that reach out to remote URLs to download malicious templates.
    *   **Fake Login Pages:** Targets HTML files that spoof legitimate portals (O365, Banking) to steal credentials.

---

## 6. Behavioral Anomalies (`behavioral`)
**Technical Purpose:** Heuristic-based detection of suspicious system actions rather than specific file signatures.

*   **Detection Capabilities:**
    *   **Process Hollowing:** Detects techniques where a legitimate process is started in a suspended state and replaced with malicious code.
    *   **API Hooking:** Identifies attempts to intercept system calls to hide malicious activity.
    *   **Reflective DLL Injection:** Targets the loading of a DLL from memory rather than disk.

---

## 7. Rootkits (`rootkit`)
**Technical Purpose:** Detects malware designed to achieve deep persistence and invisibility within the Operating System.

*   **Detection Capabilities:**
    *   **Kernel Drivers:** Identifies malicious `.sys` files (Windows) or `.ko` modules (Linux) that operate in Ring 0.
    *   **Object Hiding:** Targets techniques used to hide files, registry keys, and network connections from the OS Task Manager and File Explorer.
    *   **Boot Persistence:** Detects modifications to the Master Boot Record (MBR) or UEFI firmware.

---

## 8. Ransomware (`ransomware`)
**Technical Purpose:** Specifically targets malware that encrypts user data for extortion.

*   **Detection Capabilities:**
    *   **Encryption Loops:** Detects API calls related to crypto libraries (AES, RSA) paired with file iteration.
    *   **Backup Sabotage:** Targets commands that delete Shadow Copies (`vssadmin delete shadows`) or disable Windows Recovery.
    *   **Ransom Notes:** Identifies the creation of specific file names (e.g., `README_FOR_DECRYPT.txt`) and associated extortion strings.

---

## 9. Spyware & Surveillance (`spyware`)
**Technical Purpose:** Targets malware that monitors user activity without consent.

*   **Detection Capabilities:**
    *   **Media Capture:** Detects unauthorized access to the microphone and webcam.
    *   **Exfiltration:** Identifies the bundling of system data into `.zip` or `.cab` files for upload to C2 servers.
    *   **Tracking:** Targets cookies and registry entries used for persistent user tracking.

---

## 10. Trojans & Generic Malware (`trojans` / `malware`)
**Technical Purpose:** The core repository for multi-purpose malicious software and backdoors.

*   **Detection Capabilities:**
    *   **RATs (Remote Access Trojans):** Detects control software like `NjRAT`, `DarkComet`, and `Remcos`.
    *   **Backdoors:** Targets lightweight implants that allow remote command execution.
    *   **Downloaders/Loaders:** Identifies software whose sole purpose is to download and execute more complex malware.

---

## 11. Worms (`worms`)
**Technical Purpose:** Detects self-replicating malware designed to spread across networks.

*   **Detection Capabilities:**
    *   **Removable Media Spread:** Targets logic that creates `autorun.inf` files on USB drives.
    *   **Network Propagators:** Identifies scanning behaviors targeting SMB (EternalBlue), RDP, or local network shares.

---

## 12. Autorun & Persistence (`autorun`)
**Technical Purpose:** Detects the specific methods malware uses to survive system reboots.

*   **Detection Capabilities:**
    *   **Registry Persistence:** Targets modifications to `HKCU/HKLM` Run and RunOnce keys.
    *   **Scheduled Tasks:** Identifies the creation of automated tasks that trigger malicious binaries.
    *   **Startup Folder:** Detects the placement of shortcuts or binaries in the `Start Menu\Programs\Startup` directory.

---

## 13. Security Operations (`security`)
**Technical Purpose:** Internal telemetry and engine directives for scanning maintenance.

*   **Detection Capabilities:**
    *   **Rescan Triggers:** Directives that force the security engine to perform a deeper analysis on a file if certain low-confidence indicators are met.
    *   **Monitoring:** Rules that tag files for behavioral monitoring rather than immediate blocking.
