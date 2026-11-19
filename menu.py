#!/usr/bin/env python3
"""Menu interaktif Java4Shell lab.

Usage:
    python menu.py            # mode interaktif
    python menu.py --demo     # cetak tampilan menu lalu keluar
"""
import argparse
import subprocess
import sys
import urllib.request
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass

HERE = Path(__file__).resolve().parent
LOG = HERE / "vulnapp.log"

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║           J A V A 4 S H E L L   L A B                        ║
║           CVE-2026-114938 · OpenJDK Base64 decoder           ║
╠══════════════════════════════════════════════════════════════╣
║   [1]  Deteksi JVM + CPU + scan log          (detect.py)     ║
║   [2]  Compile + Start lab  (port 8080)      (create_lab)    ║
║   [3]  Jalankan exploit PoC                  (exploit_poc)   ║
║   [4]  Start lab mode MITIGASI (port 8081)   (create_lab)    ║
║   [5]  Status lab (health)                                   ║
║   [6]  Lihat log vulnapp.log                                 ║
║   [7]  Stop lab                                              ║
║   [0]  Keluar                                                ║
╚══════════════════════════════════════════════════════════════╝
"""

OPTIONS = {
    "1": ("Deteksi", ["detect.py"]),
    "2": ("Start lab", ["create_lab.py", "--port", "8080"]),
    "3": ("Exploit PoC", ["exploit_poc.py", "--target", "http://127.0.0.1:8080"]),
    "4": ("Start lab (mitigasi)", ["create_lab.py", "--mitigated", "--port", "8081"]),
    "7": ("Stop lab", ["create_lab.py", "--stop"]),
}


def run(script, *args):
    cmd = [sys.executable, str(HERE / script), *args]
    print(f"\n$ {' '.join(cmd)}\n" + "-" * 60)
    return subprocess.run(cmd).returncode


def status(url):
    try:
        with urllib.request.urlopen(url + "/health", timeout=4) as r:
            print(f"[+] {url}/health -> {r.status} {r.read().decode(errors='replace')}")
    except Exception as e:  # noqa: BLE001
        print(f"[-] {url} tidak bisa dijangkau: {e}")


def show_log():
    if not LOG.exists():
        print("[-] vulnapp.log belum ada. Start lab dulu.")
        return
    lines = LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    print(f"--- vulnapp.log (terakhir dari {len(lines)} baris) ---")
    for line in lines[-15:]:
        print("  " + line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    print(BANNER)
    if args.demo:
        print("[demo] tampilan menu di atas. Jalankan: python menu.py")
        return 0

    while True:
        try:
            choice = input("  Pilih menu [0-7] > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] keluar")
            return 0
        if choice == "0":
            print("Sampai jumpa, nya~")
            return 0
        if choice == "5":
            status("http://127.0.0.1:8080")
            status("http://127.0.0.1:8081")
            continue
        if choice == "6":
            show_log()
            continue
        if choice in OPTIONS:
            label, argv = OPTIONS[choice]
            print(f"\n>>> {label}")
            run(*argv)
            print()
        else:
            print("[!] pilihan tidak valid. Coba lagi.\n")


if __name__ == "__main__":
    raise SystemExit(main())
