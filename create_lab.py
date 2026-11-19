#!/usr/bin/env python3
"""Create + run the Java4Shell (CVE-2026-114938) lab web app.

Usage:
    python create_lab.py                 # compile + start on port 8080
    python create_lab.py --port 9090
    python create_lab.py --mitigated     # add -XX:-UseBASE64Intrinsics
    python create_lab.py --stop          # stop a lab started by this tool
"""
import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "VulnApp.java"
OUT = HERE / "out"
PIDFILE = HERE / "lab.pid"


def compile_lab() -> bool:
    if not SRC.exists():
        print(f"[!] source not found: {SRC}", file=sys.stderr)
        return False
    OUT.mkdir(exist_ok=True)
    cmd = ["javac", "-d", str(OUT), str(SRC)]
    print("[*] compiling:", " ".join(cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print("[!] compile failed", file=sys.stderr)
        return False
    print("[+] compiled ->", OUT)
    return True


def start_lab(port: int, mitigated: bool) -> None:
    if not (OUT / "VulnApp.class").exists() and not compile_lab():
        sys.exit(1)
    logf = HERE / "vulnapp.log"
    flags = ["-Dlab.port=%d" % port, "-Dlab.log=%s" % logf]
    if mitigated:
        flags.append("-XX:-UseBASE64Intrinsics")
    cmd = ["java", *flags, "-cp", str(OUT), "VulnApp"]
    print("[*] starting:", " ".join(cmd))
    proc = subprocess.Popen(cmd, cwd=str(HERE))
    PIDFILE.write_text(str(proc.pid))
    time.sleep(1.0)
    if proc.poll() is not None:
        print("[!] lab exited immediately", file=sys.stderr)
        sys.exit(1)
    print(f"[+] lab pid={proc.pid}  http://127.0.0.1:{port}")
    print(f"    log: {logf}")
    if mitigated:
        print("    mode: MITIGATED (-XX:-UseBASE64Intrinsics)")


def stop_lab() -> None:
    if not PIDFILE.exists():
        print("[-] no pidfile; nothing to stop")
        return
    pid = int(PIDFILE.read_text().strip())
    print(f"[*] stopping pid {pid}")
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    PIDFILE.unlink(missing_ok=True)
    print("[+] stopped")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--mitigated", action="store_true")
    ap.add_argument("--compile-only", action="store_true")
    ap.add_argument("--stop", action="store_true")
    args = ap.parse_args()

    if args.stop:
        stop_lab()
        return 0
    if args.compile_only:
        return 0 if compile_lab() else 1
    start_lab(args.port, args.mitigated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
