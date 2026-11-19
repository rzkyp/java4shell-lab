#!/usr/bin/env python3
"""Java4Shell (CVE-2026-114938) detector.

Checks:
  * installed JVM version vs affected ranges
  * CPU AVX-512 VBMI support (the intrinsic only runs there)
  * running JVMs and whether the Base64 intrinsic is disabled
  * log files for crash / corruption signatures

Usage:
    python detect.py
    python detect.py --json
    python detect.py --logs vulnapp.log /path/to/hs_err_pid1234.log
"""
import argparse
import glob
import json
import os
import platform
import re
import subprocess
import sys

AFFECTED_LINES = {
    17: ((17, 0, 6), (17, 0, 21, 1)),
    21: ((21, 0, 0), (21, 0, 13, 1)),
    25: ((25, 0, 0), (25, 0, 5, 1)),
    27: ((27, 0, 0), (27, 0, 1, 1)),
}

SIGNATURES = [
    ("base64-reject", r"java\.util\.Base64.*IllegalArgumentException|IllegalArgumentException.*Base64"),
    ("base64-decode-fail", r"IllegalArgumentException.*(Last unit|wrong 4-byte ending unit|Illegal base64|bad base64)"),
    ("jvm-crash-file", r"hs_err_pid"),
    ("sigsegv", r"SIGSEGV|SIGBUS|EXCEPTION_ACCESS_VIOLATION"),
    ("oom", r"OutOfMemoryError|OutOfMemory"),
    ("corruption", r"corrupt|corruption"),
]


def run(cmd, timeout=25):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:  # noqa: BLE001
        return ""


def parse_java_version(text):
    m = re.search(r'version\s+"([^"]+)"', text)
    if not m:
        return None
    raw = m.group(1).split()[0]
    if raw.startswith("1."):
        nums = re.findall(r"\d+", raw)
        if len(nums) >= 3:
            return (int(nums[1]), int(nums[2]), int(nums[3]))
        return None
    nums = re.findall(r"\d+", raw)
    if not nums:
        return None
    return tuple(int(x) for x in nums[:4])


def is_affected(v):
    if not v:
        return None
    line = v[0]
    if line == 8:
        return None  # only the 8u511b33-perf build; vendor specific
    if line not in AFFECTED_LINES:
        return False
    lo, hi = AFFECTED_LINES[line]
    return lo <= v < hi


def cpu_vbmi():
    """Return (supported: bool|None, note: str)."""
    if os.path.exists("/proc/cpuinfo"):
        try:
            txt = open("/proc/cpuinfo", encoding="utf-8", errors="replace").read()
        except OSError:
            txt = ""
        if "avx512_vbmi" in txt:
            return True, "cpuinfo flags contain avx512_vbmi"
        if "avx512" in txt:
            return False, "cpuinfo has avx512 but no avx512_vbmi"
        return False, "cpuinfo has no avx512 flags"

    name = ""
    if os.name == "nt":
        out = run(["powershell.exe", "-NoProfile", "-Command",
                   "(Get-CimInstance Win32_Processor).Name"])
        if out.strip():
            name = out.strip().splitlines()[0].strip()
    n = name.lower()
    if not n:
        return None, "CPU model unknown (no cpuinfo / no powershell result)"
    if "amd" in n:
        if "zen 4" in n or "zen 5" in n or re.search(r"ryzen\s+ai", n) \
                or re.search(r"ryzen\s+[579]\s+7\d{3}", n) \
                or re.search(r"epyc\s+9\d{3}", n):
            return True, f"AMD Zen4/Zen5 ({name}) - AVX-512 VBMI expected"
        if re.search(r"ryzen\s+[579]\s+[1-6]\d{3}", n) or "zen 2" in n or "zen 3" in n:
            return False, f"AMD Zen1-3 ({name}) - no AVX-512 VBMI"
        return None, f"AMD model not recognised ({name})"
    if "intel" in n:
        if re.search(r"i[3579]-11\d{3}", n):
            return True, f"Intel Tiger Lake ({name}) - AVX-512 VBMI expected"
        if re.search(r"i[3579]-1[2-9]\d{3}", n):
            return False, f"Intel Alder/Raptor/Meteor Lake ({name}) - AVX-512 absent/disabled"
        if re.search(r"i[3579]-10\d{3}", n) or re.search(r"i[3579]-9\d{3}", n):
            return False, f"Intel 9th/10th gen ({name}) - no AVX-512 VBMI"
        if "xeon" in n and re.search(r"(platinum|gold|silver)\s+[4568]\d{2}", n):
            return True, f"Intel Xeon Scalable ({name}) - AVX-512 VBMI expected"
        return None, f"Intel model not recognised ({name})"
    return None, f"unknown vendor ({name})"


def running_jvms():
    out = run(["jps", "-lv"])
    procs = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        pid, rest = parts
        procs.append({
            "pid": pid,
            "cmd": rest,
            "mitigated": "UseBASE64Intrinsics" in rest and "-XX:-" in rest,
        })
    return procs


def scan_logs(paths):
    findings = []
    for pat in paths:
        for path in glob.glob(pat):
            try:
                txt = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for label, rx in SIGNATURES:
                for m in re.finditer(rx, txt, re.IGNORECASE):
                    start = max(0, m.start() - 80)
                    findings.append({"file": path, "signature": label,
                                     "context": txt[start:m.end() + 80].replace("\n", " ")})
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--logs", nargs="*", default=["vulnapp.log", "hs_err_pid*.log"])
    args = ap.parse_args()

    ver_text = run(["java", "-version"])
    ver = parse_java_version(ver_text)
    affected = is_affected(ver)
    vbmi, vbmi_note = cpu_vbmi()
    jvms = running_jvms()
    findings = scan_logs(args.logs)

    risk = "UNKNOWN"
    if affected is False:
        risk = "LOW (JVM version not in affected range)"
    elif affected is None:
        risk = "MANUAL (Java 8 / unparsed version - check vendor build)"
    elif vbmi is False:
        risk = "MEDIUM (affected JVM, but CPU lacks AVX-512 VBMI - no intrinsic path)"
    elif vbmi is True:
        risk = "HIGH (affected JVM + AVX-512 VBMI CPU)"
    else:
        risk = "HIGH? (affected JVM, CPU capability unverified)"

    report = {
        "java_version": ".".join(map(str, ver)) if ver else None,
        "java_version_raw": ver_text.strip().splitlines()[0] if ver_text.strip() else None,
        "affected_by_cve_2026_114938": affected,
        "cpu_avx512_vbmi": vbmi,
        "cpu_note": vbmi_note,
        "risk": risk,
        "running_jvms": jvms,
        "log_findings": findings,
        "mitigation_flag": "-XX:-UseBASE64Intrinsics  (or -XX:UseAVX=2)",
    }

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print("Java4Shell detector - CVE-2026-114938")
    print("-" * 48)
    print(f"java version     : {report['java_version']}  ({report['java_version_raw']})")
    print(f"affected         : {affected}")
    print(f"cpu avx512_vbmi  : {vbmi}  [{vbmi_note}]")
    print(f"risk             : {risk}")
    print(f"mitigation       : {report['mitigation_flag']}")
    print("-" * 48)
    print(f"running JVMs     : {len(jvms)}")
    for p in jvms:
        flag = "  [mitigated]" if p["mitigated"] else ""
        print(f"  pid {p['pid']}: {p['cmd'][:110]}{flag}")
    print(f"log findings     : {len(findings)}")
    for f in findings[:15]:
        print(f"  {f['signature']} in {f['file']}: {f['context'][:120]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
