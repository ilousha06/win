import subprocess
from pathlib import Path

def scan1 ():
    scan_drive()
    part_ExtendedDriveScan()
    

def scan_drive(drive: str):
    """Scan a drive for files containing passwords / creds"""
    print(f"[i] Scanning drive {drive}:")
    
    # Patterns à rechercher
    patterns = ["*.xml", "*.ini", "*.txt", "*.cfg", "*.config"]
    exclude_dirs = [
        "AppData\\Local", "WinSxS", "ApnDatabase.xml",
        "UEV\\InboxTemplates", "Microsoft.Windows.Cloud",
        "Notepad++", "vmware", "cortana", "alphabet", "7-zip", "windows"
    ]
    
    drive_path = Path(drive + ":\\")
    for pattern in patterns:
        for file in drive_path.rglob(pattern):
            if any(excl.lower() in str(file).lower() for excl in exclude_dirs):
                continue
            try:
                with open(file, "r", errors="ignore") as f:
                    content = f.read()
                    if "password" in content.lower() or "cred" in content.lower():
                        print(file)
            except Exception:
                continue  # ignore files that cannot be read

def part_ExtendedDriveScan():
    """Extended scan for passwords and credentials"""
    # Determine drives
    result = subprocess.run(
        'wmic logicaldisk get name', shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8", errors="ignore"
    )
    drives = [line.strip() for line in result.stdout.splitlines() if line.strip() and ":" in line]
    
    for drive in drives:
        scan_drive(drive)
