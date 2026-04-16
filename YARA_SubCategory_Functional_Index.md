# YARA Sub-Category Functional & Implementation Index

This document provides a granular, technical mapping of the YARA rules within the `sub_category` folder. It is designed to assist in the precise implementation of security controls by explaining exactly what each sub-group of rules targets.

---

## 1. Initial Access & Delivery
### **Phishing Lures** (`Phishing_Lures`)
*   **Purpose:** Detects the "lure" phase.
*   **Capabilities:** Targets email headers used by common phishing kits, social engineering keywords (e.g., "urgent payment", "O365 security alert"), and malicious document templates.
*   **Implementation:** Best deployed on Email Gateways (SEG) and used to scan temporary download folders.

### **PowerShell Abuse** (`PowerShell_Abuse`)
*   **Purpose:** Detects the misuse of administrative scripting for malicious ends.
*   **Capabilities:** Identifies Base64 encoded commands, specific obfuscation patterns (e.g., character replacement, backticks), and common PowerShell-based toolkits like Empire or PowerSploit.
*   **Implementation:** Monitor via AMSI logs and command-line auditing.

### **AMSI Bypass** (`AMSI_Bypass`)
*   **Purpose:** Detects the "blinding" of Windows security features.
*   **Capabilities:** Targets small, high-impact scripts designed to patch the `AmsiScanBuffer` in memory or disable the scanning provider entirely.
*   **Implementation:** Critical for EDR memory scanning.

---

## 2. Payload Distribution & Execution
### **Downloaders & Droppers** (`Downloaders_Droppers`)
*   **Purpose:** To detect the "delivery man" malware.
*   **Capabilities:** Identifies lightweight binaries whose sole function is to connect to a C2 (Command & Control) server and pull down a larger payload (e.g., Ransomware).
*   **Implementation:** Scan for these in web browser cache, temp folders, and user AppData directories.

### **Injection Techniques** (`Injection_Techniques`)
*   **Purpose:** To detect stealthy execution.
*   **Capabilities:** Targets the "how" of execution, such as Process Hollowing (replacing legitimate code with malicious), Reflective DLL Loading (loading from memory, not disk), and Remote Thread Injection.
*   **Implementation:** Highly effective when integrated with EDR memory scanners to detect code running in unexpected memory regions.

---

## 3. High-Impact Malware Types
### **RATs (Remote Access Trojans)** (`RATs`)
*   **Purpose:** Detects interactive attacker control.
*   **Capabilities:** Targets the command structures and internal strings of notorious families like `NjRAT`, `Remcos`, `DarkComet`, and `QuasarRAT`.
*   **Implementation:** Critical for detecting active intruders on a network.

### **Infostealers** (`Infostealers`)
*   **Purpose:** Detects the industrial-scale theft of personal data.
*   **Capabilities:** Targets logic that raids Chrome/Firefox for saved logins, searches for `.txt` files containing "password", and harvests session cookies (to bypass MFA).
*   **Implementation:** Deploy on workstations to prevent data leakage of corporate credentials.

### **Banking Trojans** (`Banking_Trojans`)
*   **Purpose:** Detects financial fraud engines.
*   **Capabilities:** Specifically targets "Web Injections" (injecting fake fields into real bank websites) and capturing transaction signatures (2FA interception).

### **Crypto Ransomware** (`Crypto_Ransomware`)
*   **Purpose:** Detects file-encryption threats.
*   **Capabilities:** Focuses on the "encryption loop" (iterating through files and applying AES/RSA) and the creation of ransom notes.

---

## 4. Stealth & Persistence
### **Rootkits & Kernel Implants** (`Rootkits_Kernel`)
*   **Purpose:** To detect deep-seated invisibility.
*   **Capabilities:** Targets malicious drivers and boot-level code that attempts to hide from the operating system itself.
*   **Implementation:** Best used for low-level forensic scans of suspect machines.

### **Persistence Methods** (`Persistence_Methods`)
*   **Purpose:** Detects how malware "stays alive."
*   **Capabilities:** Targets the modification of Registry Run keys, Scheduled Tasks, and the abuse of WMI event consumers to ensure the malware starts automatically on boot.
*   **Implementation:** Periodically scan the Windows Registry and Task Scheduler definitions.

### **Evasion & Sandbox Detection** (`Evasion_Sandbox`)
*   **Purpose:** Detects malware that is "aware" of analysis.
*   **Capabilities:** Identifies code that checks for VM-specific filenames (e.g., `VBoxGuest.sys`), specific CPU instructions used by debuggers, or a low number of files on the system (indicating a fresh sandbox).
*   **Implementation:** Deploy in your malware analysis sandbox to flag "smart" malware that is trying to stay dormant during analysis.

---

## 5. Specialized Threats
### **Keyloggers** (`Keyloggers`)
*   **Purpose:** Real-time surveillance.
*   **Capabilities:** Detects the installation of global keyboard hooks (`SetWindowsHookEx`) and the creation of hidden log files to store keystrokes.

### **SQL Brute Force** (`SQL_Brute_Force`)
*   **Purpose:** Database-specific credential guessing.
*   **Capabilities:** Targets tools designed to iterate through thousands of passwords against SQL server ports.
