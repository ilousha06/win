# WinPEAS-py
**Windows Privilege Escalation Awesome Script – Python Version**  

**Original Author:** [carlospolop](https://github.com/carlospolop/PEASS-ng)

## Table of Contents

1. [Overview](#overview)  
2. [Features](#features)  
   - 2.1 [System & Environment](#system--environment)  
   - 2.2 [Users & Credentials](#users--credentials)  
   - 2.3 [Network & Security](#network--security)  
   - 2.4 [Software & Services](#software--services)  
   - 2.5 [Sensitive Files & Configurations](#sensitive-files--configurations)  
3. [Installation](#installation)  
4. [Usage](#usage)  
   - 4.1 [Full Scan](#full-scan)  
   - 4.2 [Individual Modules](#individual-modules)  
5. [Project Structure](#project-structure)  
6. [Sample Output](#sample-output)  
7. [References](#references)  
8. [Security & Precautions](#security--precautions)  
9. [Contributing](#contributing)  
10. [License](#license)  
11. [Disclaimer](#disclaimer)  

---


## Overview

**WinPEAS-py** is a **Python adaptation** of WinPEAS, a Windows enumeration script designed for **privilege escalation testing**.  

It helps **security professionals and penetration testers** identify potential privilege escalation vectors on Windows machines.  

- Compatible with **Python 3.8+**  
- **Read-only** by default  
- Modular and extensible design  
- Color-coded output for easier readability  

---

## Features

### System & Environment
- OS, architecture, updates, and hotfixes  
- Environment variables  
- Mounted drives and critical paths  
- LAPS configuration and audit info  

### Users & Credentials
- Current user and group memberships  
- Local and domain users  
- Active sessions and Kerberos tickets  
- Clipboard manager info  

### Network & Security
- Network interfaces, routing, and ARP tables  
- Open ports and firewall status  
- WSUS and update policies  
- Antivirus detection and exclusions  
- RDP and credential manager info  

### Software & Services
- Installed software and installation paths  
- Running processes and startup programs  
- Windows services and unquoted service paths  
- AlwaysInstallElevated MSI checks  
- Path vulnerabilities detection  

### Sensitive Files & Configurations
- DPAPI keys and cached passwords  
- LAPS and unattended installation files  
- SAM/SYSTEM backups  
- GPP/Group Policy passwords  
- Cloud credential files (`.aws`, `.azure`, `gcloud`)  

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/winPEAS-py.git
cd winPEAS-py
````

Optional: create a virtual environment:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt  # if required
```

---

## Usage

### Full Scan

```bash
python winpeas.py
```

Or via Python module:

```python
from winpeas import scan_all
scan_all()
```

### Individual Modules

```python
from winpeas import system_info, users, network, security

system_info.part_SystemInfo()
users.part_LocalUsers()
network.part_NetworkInterfaces()
security.part_ServiceVulnerabilities()
```

---

## Project Structure

```
winPEAS-py/
├── winpeas.py          # Main script
├── system_info.py      # System information module
├── users.py            # User enumeration
├── network.py          # Network information
├── security.py         # Security and antivirus
├── storage.py          # File and disk scanning
├── splash.py           # Banner / alerts
├── utils.py            # Utility functions
└── README.md
```

Each module corresponds to a section of the original WinPEAS script.

---

## Sample Output

```text
==================== SYSTEM INFORMATION ====================
OS: Windows 10 Enterprise 21H2
Architecture: x64
Hotfixes: KB5015807, KB5005565
Hostname: WIN10-PC

==================== USERS ====================
Current User: AdminUser
Groups: Administrators, Remote Desktop Users

==================== NETWORK ====================
Interface: Ethernet0
IP: 192.168.1.10
Firewall: Active
Listening Ports: 80, 3389

==================== SECURITY ====================
Antivirus: Windows Defender
AlwaysInstallElevated: Enabled
Unquoted Service Paths: Found for svchost.exe
```

---

## References

* Original WinPEAS: [https://github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)
* HackTricks Wiki (Windows LPE): [https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

---

## Security & Precautions

* Read-only by default
* Do **not** run on unauthorized systems
* Avoid running as Administrator unless necessary

---

## Contributing

Contributions are welcome:

* Adding new enumeration modules
* Improving output formatting
* Multi-threading for heavy scans
* Detecting new vulnerabilities or services

---

## License

MIT License – free to use, modify, and distribute.

---

## Disclaimer

**Legal use only.** Running WinPEAS-py on systems without permission is **illegal**, and authors disclaim all responsibility.

```

---

If you want, I can also **add a nice ASCII or visual module diagram** to include in the README so it looks extra professional.  

Do you want me to do that?
```
