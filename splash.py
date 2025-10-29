import subprocess

def scan ():
    part_Advisory_no_print()
    part_Advisory_no_print()

    
def run_cmd_str(cmd: str) -> str:
    """Exécute cmd et retourne stdout (sûr face aux problèmes d'encodage)."""
    try:
        completed = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        out = completed.stdout or ""
        # si tu veux aussi les erreurs, concatène completed.stderr
        return out.rstrip("\r\n")
    except Exception as e:
        return f"[run_cmd error] {e}"

def color_line_str(line: str = "", color: str = "cyan") -> str:
    """Retourne la ligne colorée (ANSI) sans l'afficher."""
    colors = {
        "black": "\033[30m", "red": "\033[31m", "green": "\033[32m",
        "yellow": "\033[33m", "blue": "\033[34m", "magenta": "\033[35m",
        "cyan": "\033[36m", "white": "\033[37m", "reset": "\033[0m"
    }
    code = colors.get(color.lower(), colors["cyan"])
    return f"{code}{line}{colors['reset']}"

def part_Splash_no_print() -> str:
    """Equivalent de part_Splash mais retourne la sortie (sans print)."""
    out_lines = []
    out_lines.append("")  # ECHO.
    # 28 fois color line (comme dans l'original) — on peut ajuster le nombre
    for _ in range(28):
        out_lines.append(color_line_str())  # ligne vide colorée
    out_lines.append("                       by carlospolop")
    out_lines.append("")
    # Advisory block
    # Remarque: part_T_Progress() était appelé dans l'original ; ici on ajoute un placeholder
    out_lines.append("[T_Progress called]")
    out_lines.append("./\\! Advisory: WinPEAS - Windows local Privilege Escalation Awesome Script")
    out_lines.append(color_line_str())
    out_lines.append(color_line_str())
    out_lines.append(color_line_str())
    out_lines.append("")
    # SystemInfo block
    out_lines.append(color_line_str())
    out_lines.append(color_line_str())
    out_lines.append("   [i] Check for vulnerabilities for the OS version with the applied patches")
    out_lines.append("   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#version-exploits")
    # execute systeminfo and capture result (no printing)
    sysinfo = run_cmd_str("systeminfo")
    out_lines.append(sysinfo if sysinfo else "(systeminfo failed or no output)")
    out_lines.append("")
    return "\n".join(out_lines)

def part_Advisory_no_print() -> str:
    """Equivalent de part_Advisory mais retourne la sortie (sans print)."""
    out_lines = []
    out_lines.append("[T_Progress called]")  # placeholder pour part_T_Progress
    out_lines.append("./\\! Advisory: WinPEAS - Windows local Privilege Escalation Awesome Script")
    out_lines.append(color_line_str())
    out_lines.append(color_line_str())
    out_lines.append(color_line_str())
    out_lines.append("")
    # SystemInfo block (réutilisé)
    out_lines.append(color_line_str())
    out_lines.append(color_line_str())
    out_lines.append("   [i] Check for vulnerabilities for the OS version with the applied patches")
    out_lines.append("   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#version-exploits")
    sysinfo = run_cmd_str("systeminfo")
    out_lines.append(sysinfo if sysinfo else "(systeminfo failed or no output)")
    out_lines.append("")
    return "\n".join(out_lines)
