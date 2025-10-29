import os
import shutil
import subprocess
from pathlib import Path

from utils import part_ColorLine

def scan():
    part_MountedDisks()
    part_Environment()
    part_InstalledSoftware()
    part_RemodeDeskCredMgr()
    part_WSUS()
    part_RunningProcesses()
    part_RunAtStartup()
    part_AlwaysInstallElevated()
    part_NetworkShares()
    part_NetworkInterfaces()
    part_NetworkUsedPorts()
    part_NetworkFirewall()
    part_ARP()
    part_NetworkRoutes()
    part_WindowsHostsFile()
    part_DNSCache()
    part_WifiCreds()

# Assure-toi d'avoir run_cmd défini ainsi (ou adapte si tu as déjà la version améliorée) :
def run_cmd(cmd, capture=True):
    try:
        completed = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        if capture:
            return (completed.stdout or "").strip(), completed.returncode
        return completed.returncode
    except Exception:
        return ("", 1) if capture else 1

# Et part_ColorLine(current_line, color) doit exister (déjà fourni dans la conversation).

# -------------------------
# Fonctions converties
# -------------------------

def part_MountedDisks():
    part_ColorLine("Mounted disks", "yellow")
    print("   [i] Maybe you find something interesting")
    # prefer wmic if present
    if shutil.which("wmic"):
        out, rc = run_cmd('wmic logicaldisk get caption')
        print(out or "(no drives found)")
    else:
        out, rc = run_cmd('fsutil fsinfo drives')
        print(out or "(fsutil not available or no drives found)")
    print()

def part_Environment():
    part_ColorLine("Environment variables", "yellow")
    print("   [i] Interesting information?")
    print()
    out, rc = run_cmd('set')  # prints environment
    print(out or "(no environment variables?)")
    print()

def part_InstalledSoftware():
    part_ColorLine("Installed software", "yellow")
    print("   [i] Some weird software? Check installed programs and install locations.")
    print("   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#applications")
    print()

    # List top-level Program Files folders (names only)
    pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    pf_x86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    def list_dir_names(p):
        if p.exists():
            try:
                for e in sorted([x.name for x in p.iterdir() if x.is_dir()]):
                    print(e)
            except Exception:
                pass

    list_dir_names(pf)
    list_dir_names(pf_x86)
    print()

    # Registry uninstall InstallLocation (may be verbose)
    out, rc = run_cmd(r'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s')
    if out:
        # crude filter for InstallLocation lines
        for line in out.splitlines():
            if "InstallLocation" in line and ":\\ " in line:
                print(line.strip())
    out2, rc2 = run_cmd(r'reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ /s')
    if out2:
        for line in out2.splitlines():
            if "InstallLocation" in line and ":\\ " in line:
                print(line.strip())

    # SCCM client heuristic
    if Path(r"C:\Windows\CCM\SCClient.exe").exists():
        print("SCCM is installed (C:\\Windows\\CCM\\SCClient.exe) — installers may run as SYSTEM")
    print()

def part_RemodeDeskCredMgr():
    part_ColorLine("Remote Desktop Credential Manager", "yellow")
    print("   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#remote-desktop-credential-manager")
    path = Path(os.environ.get("LOCALAPPDATA", "")) / "Local" / "Microsoft" / "Remote Desktop Connection Manager" / "RDCMan.settings"
    if path.exists():
        print(f"Found: {path} — check .rdg files for credentials")
    else:
        print("(RDCMan.settings not found)")
    print()

def part_WSUS():
    part_ColorLine("WSUS settings", "yellow")
    print("   [i] You can inject fake updates into non-SSL WSUS traffic (WSUXploit)")
    print("   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#wsus")
    out, rc = run_cmd(r'reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\ 2>nul')
    if out:
        # simple grep for wuserver/http
        for l in out.splitlines():
            if "WUServer" in l or "wuserver" in l.lower() or "http://" in l.lower():
                print(l.strip())
    else:
        print("(no WSUS policy keys found or access denied)")
    print()

def part_RunningProcesses():
    part_ColorLine("Running processes", "yellow")
    print("   [i] Something unexpected is running? Check for vulnerabilities")
    print("   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#running-processes")
    out, rc = run_cmd('tasklist /SVC')
    print(out or "(tasklist failed or empty)")
    print()

def part_RunAtStartup():
    part_ColorLine("Run at startup", "yellow")
    print("   [i] Check autoruns locations and registry Run keys")
    print("   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#run-at-startup")
    for key in [
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    ]:
        out, rc = run_cmd(f'reg query {key} 2>nul')
        if out:
            print(f"--- {key} ---")
            print(out)
    print()

def part_AlwaysInstallElevated():
    part_ColorLine("AlwaysInstallElevated", "yellow")
    print("   [i] If value = 1 you can install a .msi with admin privileges")
    print("   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated-1")
    out1, rc1 = run_cmd(r'reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul')
    out2, rc2 = run_cmd(r'reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul')
    print(out1 or "(HKCU: not set or access denied)")
    print(out2 or "(HKLM: not set or access denied)")
    print()

def part_NetworkShares():
    part_ColorLine("Network shares", "yellow")
    out, rc = run_cmd('net share')
    print(out or "(no shares or access denied)")
    print()

def part_NetworkInterfaces():
    part_ColorLine("Network interfaces", "yellow")
    out, rc = run_cmd('ipconfig /all')
    print(out or "(ipconfig failed)")
    print()

def part_NetworkUsedPorts():
    part_ColorLine("Network used ports", "yellow")
    print("   [i] Check for services restricted from the outside")
    out, rc = run_cmd('netstat -ano | findstr /i listen')
    print(out or "(no listening ports or command failed)")
    print()

def part_NetworkFirewall():
    part_ColorLine("Network firewall", "yellow")
    out1, rc1 = run_cmd('netsh firewall show state')
    out2, rc2 = run_cmd('netsh firewall show config')
    print(out1 or "(no firewall state or command missing)")
    print(out2 or "(no firewall config or command missing)")
    print()

def part_ARP():
    part_ColorLine("ARP table", "yellow")
    out, rc = run_cmd('arp -A')
    print(out or "(arp failed or empty)")
    print()

def part_NetworkRoutes():
    part_ColorLine("Network routes", "yellow")
    out, rc = run_cmd('route print')
    print(out or "(route print failed)")
    print()

def part_WindowsHostsFile():
    part_ColorLine("Windows hosts file", "yellow")
    hosts = Path(r"C:\WINDOWS\System32\drivers\etc\hosts")
    if hosts.exists():
        try:
            with open(hosts, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.strip().startswith("#") and line.strip():
                        print(line.rstrip())
        except Exception:
            print("(cannot read hosts file)")
    else:
        print("(hosts file not found)")
    print()

def part_DNSCache():
    part_ColorLine("DNS cache", "yellow")
    out, rc = run_cmd(r'ipconfig /displaydns | findstr "Record" | findstr "Name Host"')
    print(out or "(no DNS cache entries or command failed)")
    print()

def part_WifiCreds():
    part_ColorLine("Wifi credentials (profiles)", "yellow")
    # This replicates the batch pipeline: enumerate profiles then show key=clear for each
    out, rc = run_cmd(r'netsh wlan show profiles')
    if not out:
        print("(no wireless profiles or netsh not available)")
        print()
        return

    # parse profile names
    profiles = []
    for line in out.splitlines():
        line = line.strip()
        # localized outputs vary; try common token "All User Profile" or "Profile"
        if ":" in line and ("Profile" in line or "All User Profile" in line or "Profil" in line):
            # get after colon
            try:
                name = line.split(":", 1)[1].strip()
                if name:
                    profiles.append(name)
            except Exception:
                continue

    # fallback: parse lines containing "Profile" token more loosely
    if not profiles:
        for line in out.splitlines():
            if "Profile" in line or "Profil" in line:
                token = line.split(":")[-1].strip()
                if token:
                    profiles.append(token)

    # for each profile, show details
    for p in profiles:
        print(f"--- Profile: {p} ---")
        details, rc = run_cmd(fr'netsh wlan show profile name="{p}" key=clear')
        if details:
            # print only relevant lines (SSID, Cipher, Key Content)
            for l in details.splitlines():
                if ("SSID" in l and "name" in l.lower()) or "Cipher" in l or "Key Content" in l or "Content" in l:
                    print(l.strip())
        else:
            print("(could not retrieve profile details)")
        print()
