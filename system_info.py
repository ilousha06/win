import subprocess

def scan ():
    part_SystemInfo()
    part_ListHotFixes()
    part_DateAndTime()
    part_AuditSettings()
    part_WEFSettings()
    part_LAPSInstallCheck()
    part_WindowsLAPSInstallCheck()
    part_LSAProtectionCheck()
    part_LSACredentialGuard()
    part_LogonCredentialsPlainInMemory()
    part_CachedCreds()
    part_UACSettings()


def run_cmd(cmd):
    """Exécute une commande et retourne la sortie."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Erreur: {e}"

def part_ColorLine():
    print("="*80)

def part_SystemInfo():
    part_ColorLine()
    print("[i] Check OS version and installed patches for vulnerabilities")
    print("[?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#version-exploits")
    print(run_cmd(["systeminfo"]))
    print()

def part_ListHotFixes():
    part_ColorLine()
    print("[i] Listing installed HotFixes")
    try:
        result = run_cmd(["powershell", "-Command", "Get-HotFix | Format-Table -AutoSize"])
        print(result)
    except Exception as e:
        print(f"Erreur HotFixes: {e}")
    print()

def part_DateAndTime():
    part_ColorLine()
    print("[i] Local date and time")
    print(run_cmd("date /T"))
    print(run_cmd("time /T"))
    print()

def part_AuditSettings():
    part_ColorLine()
    print("[i] Audit settings")
    print(run_cmd('reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"'))
    print()

def part_WEFSettings():
    part_ColorLine()
    print("[i] Event Forwarding settings")
    print(run_cmd('reg query "HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager"'))
    print()

def part_LAPSInstallCheck():
    part_ColorLine()
    print("[i] LAPS installation")
    print(run_cmd('reg query "HKLM\\Software\\Policies\\Microsoft Services\\AdmPwd" /v AdmPwdEnabled'))
    print()

def part_WindowsLAPSInstallCheck():
    part_ColorLine()
    print("[i] Windows LAPS Backup settings")
    print(run_cmd('reg query "HKLM\\Software\\Microsoft\\Policies\\LAPS" /v BackupDirectory'))
    print(run_cmd('reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS" /v BackupDirectory'))
    print()

def part_LSAProtectionCheck():
    part_ColorLine()
    print("[i] LSA Protection (RunAsPPL)")
    print(run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA" /v RunAsPPL'))
    print()

def part_LSACredentialGuard():
    part_ColorLine()
    print("[i] LSACredentialGuard (LsaCfgFlags)")
    print(run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA" /v LsaCfgFlags'))
    print()

def part_LogonCredentialsPlainInMemory():
    part_ColorLine()
    print("[i] Plain-text credentials in memory (WDigest)")
    print(run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential'))
    print()

def part_CachedCreds():
    part_ColorLine()
    print("[i] Cached credentials count (requires SYSTEM)")
    print(run_cmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v CACHEDLOGONSCOUNT'))
    print()

def part_UACSettings():
    part_ColorLine()
    print("[i] UAC status (EnableLUA = 0x1 means enabled)")
    print(run_cmd('reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA'))
    print()

# --- Exemple d'exécution ---
if __name__ == "__main__":
    part_SystemInfo()
    part_ListHotFixes()
    part_DateAndTime()
    part_AuditSettings()
    part_WEFSettings()
    part_LAPSInstallCheck()
    part_WindowsLAPSInstallCheck()
    part_LSAProtectionCheck()
    part_LSACredentialGuard()
    part_LogonCredentialsPlainInMemory()
    part_CachedCreds()
    part_UACSettings()
