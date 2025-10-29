# win_audit.py
import os
import subprocess
import shutil
from utils import part_ColorLine
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

def scan():
    part_AVSettings()
    part_PSSettings()
    part_ServiceVulnerabilities()
    part_ServiceBinaryPermissions()
    part_CheckRegistryModificationAbilities()
    part_UnquotedServicePaths()
    part_PATHenvHijacking()
    part_WindowsCredentials()
    part_DPAPIMasterKeys()
    part_UnattendedFiles()
    part_SAMSYSBackups()
    part_McAffeeSitelist()
    part_GPPPassword()
    part_CloudCreds()
    part_AppCMD()
    part_RegFilesCredentials()

# -----------------------
# Helper: run command
# -----------------------
def run_cmd(cmd, capture=False):
    """
    Execute a shell command (Windows style).
    - capture=True -> return stdout (str), else returns process.returncode
    """
    try:
        # Here !
        print("Cmd: ", cmd)
        completed = subprocess.run(cmd, shell=True, check=False,text=True,
                                   stdout=subprocess.PIPE if capture else None,
                                   stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
                                   universal_newlines=True)
        if capture:
            out = completed.stdout.decode('utf-8', errors='ignore')
            err = completed.stderr.decode('utf-8', errors='ignore')
            return out.strip(), completed.returncode
        return completed.returncode
    except Exception as e:
        return ("", 1) if capture else 1


# -----------------------
# Utilities filesystem / search
# -----------------------
def find_files_in_roots(patterns, roots, max_workers=4):
    """Cherche récursivement les noms exacts (patterns: list of str) sous chaque root. Retourne generator de Path."""
    def scan(root):
        found = []
        r = Path(root)
        if not r.exists():
            return found
        # r.rglob for each pattern
        for pat in patterns:
            # treat patterns that look like extensions vs exact names
            for p in r.rglob(pat):
                found.append(p)
        return found

    scan(roots[0])
    # Here !
    #with ThreadPoolExecutor(max_workers=max_workers) as ex:
    #    futures = [ex.submit(scan, root) for root in roots]
    #    for f in futures:
    #        for p in f.result():
    #            yield p


# -----------------------
# Functions converted
# -----------------------

def part_AVSettings():
    """Equivalent de :AVSettings — liste antivirus + exclusions Defender."""
    part_ColorLine("AV Settings", "yellow")

    # Check wmic availability
    if shutil.which("wmic"):
        part_ColorLine("WMIC présent — récupération des produits AV", "cyan")
        # WMIC output may be large; capture & print
        out, rc = run_cmd('WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List', capture=True)
        if out:
            print(out)
    else:
        part_ColorLine("WMIC absent — utilisation de PowerShell CIM", "cyan")
        out, rc = run_cmd('powershell -command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName"', capture=True)
        if out:
            print(out)

    part_ColorLine("Checking for defender whitelisted PATHS", "yellow")
    out, rc = run_cmd(r'reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" 2>nul', capture=True)
    if out:
        print(out)
    else:
        print("(no Defender path exclusions found or access denied)")


def part_PSSettings():
    """Equivalent de :PSSettings — versions PS, logging, history, mounted disks."""
    part_ColorLine("PowerShell Settings", "yellow")

    print("PowerShell v2 Version:")
    out, rc = run_cmd(r'REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine /v PowerShellVersion 2>nul', capture=True)
    print(out or "(none)")

    print("PowerShell v5 Version:")
    out, rc = run_cmd(r'REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine /v PowerShellVersion 2>nul', capture=True)
    print(out or "(none)")

    print("Transcriptions Settings:")
    out, rc = run_cmd(r'REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription 2>nul', capture=True)
    print(out or "(none)")

    print("Module logging settings:")
    out, rc = run_cmd(r'REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging 2>nul', capture=True)
    print(out or "(none)")

    print("Scriptblock logging settings:")
    out, rc = run_cmd(r'REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging 2>nul', capture=True)
    print(out or "(none)")

    print()
    part_ColorLine("PS default transcript history", "cyan")
    transcripts_dir = Path(os.environ.get("SystemDrive", "C:")) / "transcripts"
    if transcripts_dir.exists():
        for p in transcripts_dir.iterdir():
            print(p)
    else:
        print("(no transcripts directory)")

    print()
    part_ColorLine("Checking PS history file", "cyan")
    ps_hist = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
    print(ps_hist if ps_hist.exists() else "(no history file)")

    # Mounted disks (try wmic else fsutil)
    part_ColorLine("Mounted disks", "yellow")
    if shutil.which("wmic"):
        out, rc = run_cmd('wmic logicaldisk get caption', capture=True)
        print(out or "(none)")
    else:
        out, rc = run_cmd('fsutil fsinfo drives', capture=True)
        print(out or "(none)")


def part_ServiceVulnerabilities():
    """Commentaires originaux sur accesschk (outil sysinternals). On se contente d'afficher l'info."""
    part_ColorLine("Service vulnerabilities (accesschk hints)", "yellow")
    print("[i] Cette section mentionnait l'utilisation d'accesschk.exe (Sysinternals).")
    print("[i] Si accesschk est dans le PATH, exécuter manuellement : accesschk.exe -uwcqv \"Authenticated Users\" * /accepteula")
    # Rien d'automatique ici (outil externe)


def part_ServiceBinaryPermissions():
    """Recherche de services avec chemin binaire non System32 et vérifie permissions via icacls si possible."""
    part_ColorLine("Service binary permissions", "yellow")
    print("Référence: https://book.hacktricks.wiki/.../services (voir la doc)")

    if shutil.which("wmic"):
        # WMIC path extraction (approx)
        cmd = 'wmic service list full | findstr /I "pathname" | findstr /I /V "system32"'
        out, rc = run_cmd(cmd, capture=True)
        if out:
            # on récupère les chemins entre quotes si possible
            for line in out.splitlines():
                # line contains something like PathName= "C:\Program Files\...exe"
                if "=" in line:
                    _, val = line.split("=", 1)
                    val = val.strip().strip('"')
                    p = Path(val)
                    if p.exists() and shutil.which("icacls"):
                        ic_out, rc2 = run_cmd(f'icacls "{p}"', capture=True)
                        if ic_out and any(x.lower() in ic_out.lower() for x in ["everyone", "authenticated users", "users", os.getlogin().lower()]):
                            print(p)
    else:
        # PowerShell alternative: list services and PathName; filter out system32
        cmd = 'powershell -command "Get-CimInstance -ClassName Win32_Service | Where-Object {$_.PathName -and $_.PathName -notlike \'*system32*\'} | Select-Object -ExpandProperty PathName"'
        out, rc = run_cmd(cmd, capture=True)
        if out:
            for line in out.splitlines():
                # le PathName peut contenir arguments -> on prend le premier token entre quotes ou espace
                line = line.strip()
                if not line:
                    continue
                # if quoted, remove quotes
                if line.startswith('"') and '"' in line[1:]:
                    path_str = line.split('"')[1]
                else:
                    path_str = line.split()[0]
                    path_str = path_str.strip('"')
                p = Path(path_str)
                if p.exists() and shutil.which("icacls"):
                    ic_out, rc2 = run_cmd(f'icacls "{p}"', capture=True)
                    if ic_out and any(x.lower() in ic_out.lower() for x in ["everyone", "authenticated users", "users", os.getlogin().lower()]):
                        print(p)
    print()


def part_CheckRegistryModificationAbilities():
    """Tente de détecter si on peut sauvegarder/restaurer des clés de services (approche dangereuse -> on n'exécute pas de restore)."""
    part_ColorLine("Check Registry Modification Abilities", "yellow")
    print("Attention: l'opération originale sauvegardait/restaurait des hives (danger).")
    print("Ici on teste simplement la possibilité de lire les clés de services.")
    out, rc = run_cmd('reg query hklm\\system\\currentcontrolset\\services 2>nul', capture=True)
    if out:
        print("Accès lecture possible sur les services (liste non affichée).")
    else:
        print("Lecture des services impossible ou restreinte.")


def part_UnquotedServicePaths():
    """Recherche de services avec chemins non-quotés (heuristique)."""
    part_ColorLine("Unquoted Service Paths", "yellow")
    print("Recherche heuristique des chemins de services non-quotés (peut produire faux-positifs).")

    # liste des services
    cmd = 'sc query state= all'
    out, rc = run_cmd(cmd, capture=True)
    services = []
    if out:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                services.append(line.split(":", 1)[1].strip())

    # Pour chaque service, récupérer BINARY_PATH_NAME
    for s in services:
        cmd2 = f'sc qc "{s}"'
        out2, rc2 = run_cmd(cmd2, capture=True)
        if not out2:
            continue
        for l in out2.splitlines():
            if "BINARY_PATH_NAME" in l:
                # extrait le chemin
                _, val = l.split(":", 1)
                val = val.strip()
                # ignorer system32
                if "system32" in val.lower():
                    continue
                # heuristique: s'il y a un espace non entouré de quotes -> rapport possible
                if '"' not in val and any(c == " " for c in val):
                    print(f"Service: {s} -> {val}")
                    # try icacls if exists (permissions)
                    if shutil.which("icacls"):
                        # prendre premier token comme chemin
                        path_token = val.split()[0].strip('"')
                        p = Path(path_token)
                        if p.exists():
                            ic_out, _ = run_cmd(f'icacls "{p}"', capture=True)
                            if ic_out and any(x.lower() in ic_out.lower() for x in ["everyone", "authenticated users", os.getlogin().lower()]):
                                print(f"  Permissions suspectes sur: {p}")
                    print()


def part_PATHenvHijacking():
    """Inspecte chaque dossier du PATH et tente icacls pour repérer permissions faibles."""
    part_ColorLine("PATH env hijacking scan", "yellow")
    print("Examining PATH entries...")
    path_env = os.environ.get("PATH", "")
    entries = [p.strip('"') for p in path_env.split(";") if p]
    for entry in entries:
        p = Path(entry)
        if p.exists():
            if shutil.which("icacls"):
                ic_out, _ = run_cmd(f'icacls "{p}"', capture=True)
                if ic_out and any(x.lower() in ic_out.lower() for x in ["everyone", "authenticated users", "users", os.getlogin().lower()]):
                    print(f"{p} -> permissions faibles détectées")
    print()


def part_WindowsCredentials():
    """Equivalent de :WindowsCredentials (liste cmdkey)."""
    part_ColorLine("Windows Credentials (cmdkey)", "yellow")
    out, rc = run_cmd("cmdkey /list", capture=True)
    print(out or "(no cmdkey entries or access denied)")
    print()


def part_DPAPIMasterKeys():
    """Liste des dossiers Protect où peuvent se trouver des masterkeys DPAPI."""
    part_ColorLine("DPAPI MasterKeys", "yellow")
    appdata = Path(os.environ.get("APPDATA", ""))
    localapp = Path(os.environ.get("LOCALAPPDATA", ""))
    for base in [appdata, localapp]:
        if base:
            p = base / "Microsoft" / "Protect"
            if p.exists():
                print(f"{p}:")
                for child in p.iterdir():
                    print("  ", child)
            else:
                print(f"{p} (no)")
    print()


def part_UnattendedFiles():
    """Check des fichiers Unattend / Sysprep classiques."""
    part_ColorLine("Unattended files", "yellow")
    windir = Path(os.environ.get("WINDIR", "C:\\Windows"))
    candidates = [
        windir / "sysprep" / "sysprep.xml",
        windir / "sysprep" / "sysprep.inf",
        windir / "sysprep.inf",
        windir / "Panther" / "Unattended.xml",
        windir / "Panther" / "Unattend.xml",
        windir / "Panther" / "Unattend" / "Unattend.xml",
        windir / "Panther" / "Unattend" / "Unattended.xml",
        windir / "System32" / "Sysprep" / "unattend.xml",
        windir / "System32" / "Sysprep" / "unattended.xml",
        windir.parent / "unattend.txt",
        windir.parent / "unattend.inf"
    ]
    for c in candidates:
        if c.exists():
            print(f"{c} exists.")
    print()


def part_SAMSYSBackups():
    """Vérifie fichiers SAM / SYSTEM de sauvegarde classiques."""
    part_ColorLine("SAM/SYSTEM backups", "yellow")
    windir = Path(os.environ.get("WINDIR", "C:\\Windows"))
    candidates = [
        windir / "repair" / "SAM",
        windir / "System32" / "config" / "RegBack" / "SAM",
        windir / "System32" / "config" / "SAM",
        windir / "repair" / "SYSTEM",
        windir / "System32" / "config" / "SYSTEM",
        windir / "System32" / "config" / "RegBack" / "SYSTEM"
    ]
    for c in candidates:
        if c.exists():
            print(f"{c} exists.")
    print()


def part_McAffeeSitelist():
    """Recherche SiteList.xml dans ProgramFiles, Users, Documents and Settings (multi-threaded)."""
    part_ColorLine("McAffee SiteList", "yellow")
    roots = []
    pf = os.environ.get("ProgramFiles")
    pfx86 = os.environ.get("ProgramFiles(x86)")
    if pf: roots.append(pf)
    if pfx86: roots.append(pfx86)
    roots.append(Path(os.environ.get("WINDIR", "C:\\Windows")).parent / "Documents and Settings")
    roots.append(Path(os.environ.get("SystemDrive", "C:")) / "Users")

    for p in find_files_in_roots(["SiteList.xml"], roots):
        print(p)
    print()


def part_GPPPassword():
    """Recherche fichiers GPP dans les dossiers Group Policy history."""
    part_ColorLine("GPP Passwords (Group Policy history files)", "yellow")
    roots = [
        Path(os.environ.get("SystemDrive", "C:")) / "Microsoft" / "Group Policy" / "history",
        Path(os.environ.get("WINDIR", "C:\\Windows")).parent / "Documents and Settings" / "All Users" / "Application Data" / "Microsoft" / "Group Policy" / "history"
    ]
    patterns = ["Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml"]
    for p in find_files_in_roots(patterns, roots):
        print(p)
    print()


def part_CloudCreds():
    """Recherche de fichiers de credentials cloud dans Users / Documents and Settings."""
    part_ColorLine("Cloud credentials scan", "yellow")
    patterns = [".aws", "credentials", "gcloud", "credentials.db", "legacy_credentials", "access_tokens.db", ".azure", "accessTokens.json", "azureProfile.json"]
    roots = [
        Path(os.environ.get("SystemDrive", "C:")) / "Users",
        Path(os.environ.get("WINDIR", "C:\\Windows")).parent / "Documents and Settings"
    ]
    for p in find_files_in_roots(patterns, roots):
        print(p)
    print()


def part_AppCMD():
    """Vérifie si appcmd.exe existe."""
    part_ColorLine("AppCMD", "yellow")
    sysroot = Path(os.environ.get("systemroot", os.environ.get("WINDIR", "C:\\Windows")))
    maybe = sysroot / "system32" / "inetsrv" / "appcmd.exe"
    if maybe.exists():
        print(f"{maybe} exists.")
    else:
        print("(appcmd.exe not found)")
    print()


def part_RegFilesCredentials():
    """Recherche d'entrées de registre souvent associées à des credentials (ex: WinVNC3)."""
    part_ColorLine("Registry / Files credentials", "yellow")
    print("Looking inside HKCU\\Software\\ORL\\WinVNC3\\Password")
    out, rc = run_cmd(r'reg query HKCU\Software\ORL\WinVNC3\Password 2>nul', capture=True)
    print(out or "(not found or access denied)")


# -----------------------
# Example: exécution rapide
# -----------------------
if __name__ == "__main__":
    # Exécute quelques checks pour démonstration
    part_AVSettings()
    part_PSSettings()
    part_McAffeeSitelist()
    part_CloudCreds()
    part_DPAPIMasterKeys()
