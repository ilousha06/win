# Auto-converted winPEAS.bat -> winPEAS.py
# Each batch label block is converted into a Python function.
# Execution uses subprocess to run original Windows commands.
import os, subprocess, shlex, sys
from pathlib import Path
import network
import security
import splash
import storage
import system_info
import users

def run_cmd(cmd, check=False):
    print(f"> {cmd}")
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.stdout:
            print(res.stdout.strip())
        if res.stderr:
            print(res.stderr.strip(), file=sys.stderr)
        if check and res.returncode != 0:
            raise subprocess.CalledProcessError(res.returncode, cmd)
        return res
    except Exception as e:
        print(f"Error running: {cmd}: {e}", file=sys.stderr)
        return None

def set_env_from_set_line(line):
    # Handle lines like: SET "VAR=VALUE" or SET VAR=VALUE
    m = None
    if 'SET ' in line:
        after = line.split('SET',1)[1].strip()
        if after.startswith('"') and after.endswith('"'):
            after = after[1:-1]
        if '=' in after:
            var,val = after.split('=',1)
            var=var.strip().strip('"')
            val=val.strip().strip('"')
            os.environ[var]=val
            print(f"[env] {var}={val}")

if __name__ == "__main__":
    # You can call functions directly, e.g. part_Splash()
    network.scan()
    security.scan()
    splash.scan()
    storage.scan1()
    system_info.scan()
    users.scan()

    print("WinPEAS converted script. Call desired part functions as needed.")
