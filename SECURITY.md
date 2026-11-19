# Security Policy — Java4Shell Lab

## Scope

Repo ini adalah **alat lab edukasi** untuk CVE-2026-114938 (Java4Shell).
Masalah keamanan yang dilaporkan ke repo ini harus berkaitan dengan:

- bug pada `VulnApp.java`, `detect.py`, `exploit_poc.py`, `create_lab.py`, atau `menu.py`
- akurasi deteksi (false positive / false negative)
- Dockerfile / aset lab

## Bukan laporan kerentanan produksi

Jangan laporkan kerentanan pada perangkat lunak pihak ketiga (OpenJDK, Keycloak,
Jenkins, dsb.) di sini. Laporkan ke vendor/CNA yang bersangkutan.

## Melaporkan

1. Buka issue dengan label `bug` atau `detection`.
2. Sertakan: versi alat (`python detect.py --json`), OS, versi Python/JDK,
   langkah reproduksi, dan keluaran yang diharapkan vs aktual.
3. Jangan sertakan data pribadi atau target yang tidak berizin.

## Tanggapan

- Kami usahakan merespons dalam 7 hari kerja.
- Perbaikan mayor akan dirilis sebagai commit + tag baru.

## Penggunaan yang diizinkan

Hanya lingkungan lab / aset sendiri / uji yang berizin. Lihat [LICENSE](LICENSE).
