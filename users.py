import os
import subprocess
from utils import part_ColorLine

def scan():
    part_BasicUserInfo()
    part_BasicUserInfoUsers()
    part_BasicUserInfoGroups()
    part_BasicUserInfoAdminGroups()
    part_BasicUserInfoLoggedUser()
    part_KerberosTickets()
    part_CurrentClipboard()

def run_cmd(cmd, capture=True):
    """
    Execute a shell command (Windows).
    - capture=True -> return (stdout_str, returncode)
    - capture=False -> return returncode
    Uses text=True + encoding utf-8 + errors='replace' to avoid decoding exceptions.
    """
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
            out = completed.stdout or ""
            err = completed.stderr or ""
            # combine stdout/stderr if you want both; here we return stdout and code
            return out.strip(), completed.returncode
        return completed.returncode
    except Exception as e:
        return ("", 1) if capture else 1


def part_BasicUserInfo():
    """Converted from label :BasicUserInfo"""
    part_ColorLine("Basic user info", "yellow")  # CALL :ColorLine

    print("   [i] Check if you are inside the Administrators group or if you have enabled any privilege tokens")
    print("   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#users--groups")
    print()

    username = os.environ.get("USERNAME", "%USERNAME%")
    # net user %username%
    out, rc = run_cmd(f'net user "{username}"')
    print(out or "(no output / access denied)")

    # net user %USERNAME% /domain (may fail on non-domain machines)
    out, rc = run_cmd(f'net user "{username}" /domain')
    if out:
        print(out)
    else:
        print("(no domain info or not joined to a domain)")

    # whoami /all
    out, rc = run_cmd('whoami /all')
    print(out or "(whoami failed or no output)")
    print()


def part_BasicUserInfoUsers():
    """Converted from label :BasicUserInfoUsers"""
    part_ColorLine("Local users", "yellow")
    out, rc = run_cmd('net user')
    print(out or "(no local users / access denied)")
    print()


def part_BasicUserInfoGroups():
    """Converted from label :BasicUserInfoGroups"""
    part_ColorLine("Local groups", "yellow")
    out, rc = run_cmd('net localgroup')
    print(out or "(no local groups / access denied)")
    print()


def part_BasicUserInfoAdminGroups():
    """Converted from label :BasicUserInfoAdminGroups"""
    part_ColorLine("Administrators group membership", "yellow")
    # localized group names: Administrators (EN), Administradores (ES), ...
    out, rc = run_cmd('net localgroup Administrators')
    if out:
        print(out)
    else:
        print("(Administrators group not found or access denied)")

    out2, rc2 = run_cmd('net localgroup Administradores')
    if out2:
        print(out2)
    # don't print a second message to avoid clutter if not present
    print()


def part_BasicUserInfoLoggedUser():
    """Converted from label :BasicUserInfoLoggedUser"""
    part_ColorLine("Logged on users (quser)", "yellow")
    out, rc = run_cmd('quser')
    print(out or "(no interactive sessions or quser not available)")
    print()


def part_KerberosTickets():
    """Converted from label :KerberosTickets"""
    part_ColorLine("Kerberos tickets (klist)", "yellow")
    out, rc = run_cmd('klist')
    print(out or "(no tickets or klist not available)")
    print()


def part_CurrentClipboard():
    """Converted from label :CurrentClipboard"""
    part_ColorLine("Clipboard contents", "yellow")
    print("   [i] Any passwords inside the clipboard?")
    out, rc = run_cmd(r'powershell -command "Get-Clipboard"')
    # Trim and print; if empty, mention it
    if out:
        print(out)
    else:
        print("(clipboard empty or access denied)")
    print()
