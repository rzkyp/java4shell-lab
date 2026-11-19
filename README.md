# Java4Shell Lab — CVE-2026-114938

Lab lokal untuk mempelajari dan mendeteksi **Java4Shell** (OpenJDK Base64 decoder
heap overflow, pre-auth RCE diklaim pada JVM AVX-512 VBMI). Hanya untuk
**penggunaan lab/resmi yang berwenang**.

> Batas penting: **tidak ada exploit RCE publik** untuk CVE ini. Calif menahan
> exploit chain-nya. PoC di repo ini memicu **crash/korupsi**, bukan RCE.
> Anggap klaim "RCE cukup kirim link" sebagai hoax.

## File
| File | Fungsi |
|---|---|
| `VulnApp.java` | Web app renten (endpoint `/decode`, `/decode-basic`, `/health`) |
| `menu.py` | Menu interaktif: start lab, deteksi, PoC, status, log |
| `create_lab.py` | Compile + jalankan web app; `--mitigated` untuk mode mitigasi |
| `detect.py` | Cek versi JVM, CPU AVX-512 VBMI, JVM berjalan, scan log |
| `exploit_poc.py` | Kirim payload Base64 cacat, deteksi crash/reject; `--explain` |
| `Dockerfile` | Image lab (jalankan di host AVX-512 VBMI) |

## Kebutuhan pemicu
- JVM teraffeksi: OpenJDK **17.0.6 – 17.0.21**, **21 < 21.0.13.1**,
  **25 < 25.0.5.1**, **27 < 27.0.1.1**, Oracle Java SE 8u511b33-perf.
- CPU **x86-64 dengan AVX-512 VBMI** (Intel Ice Lake+/Tiger Lake, AMD Zen 4+).
- Tanpa AVX-512 VBMI, intrinsic rentan **tidak pernah dipakai** → tidak crash.

## Mulai
```bash
# 0. menu interaktif (paling gampang)
python menu.py

# 1. deteksi dulu
python detect.py

# 2. buat + jalankan web rentan (port 8080)
python create_lab.py

# 3. uji PoC
python exploit_poc.py --target http://127.0.0.1:8080
python exploit_poc.py --explain

# 4. mode mitigasi (bandingkan)
python create_lab.py --stop
python create_lab.py --mitigated --port 8081
python exploit_poc.py --target http://127.0.0.1:8081
```

## Deteksi (tim merah/biru)
```bash
python detect.py --json
python detect.py --logs vulnapp.log hs_err_pid*.log
```
Signature yang dicari: `IllegalArgumentException` Base64, `hs_err_pid*`,
`SIGSEGV`/`EXCEPTION_ACCESS_VIOLATION`, `OutOfMemoryError`, korupsi.

## Mitigasi
- Patch vendor: Oracle `17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1`,
  `8u513-perf`; Corretto `17.0.21.1.2` dll; Zulu `17.70.201` dll.
- **Red Hat OpenJDK / Temurin / Microsoft / Liberica: belum ada fix** (per 19 Nov 2026).
- Sementara: `-XX:-UseBASE64Intrinsics` atau `-XX:UseAVX=2`, lalu restart JVM.

## Docker (host AVX-512)
```bash
docker build -t java4shell-lab .
docker run --rm -p 8080:8080 java4shell-lab
python exploit_poc.py --target http://127.0.0.1:8080
```
