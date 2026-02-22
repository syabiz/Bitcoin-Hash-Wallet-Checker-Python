# 🐍 Bitcoin / Litecoin wallet.dat — Batch Password Checker (Python)

> **Alat Edukasi** · Python 3 · CPU & GPU  
> Untuk: mahasiswa kriptografi, tim forensik digital, developer blockchain

---

## 📋 Daftar Isi

1. [Apa Itu Alat Ini?](#1-apa-itu-alat-ini)
2. [Kebutuhan & Instalasi](#2-kebutuhan--instalasi)
3. [Cara Cepat Mulai](#3-cara-cepat-mulai)
4. [Format File Input](#4-format-file-input)
5. [Cara Kerja — Algoritma](#5-cara-kerja--algoritma)
6. [Bug yang Diperbaiki & Catatan Teknis](#6-bug-yang-diperbaiki--catatan-teknis)
7. [Mode CPU vs GPU](#7-mode-cpu-vs-gpu)
8. [Referensi Argumen CLI](#8-referensi-argumen-cli)
9. [Format Output](#9-format-output)
10. [Mengekstrak Hash dari wallet.dat](#10-mengekstrak-hash-dari-walletdat)
11. [Keamanan & Etika Penggunaan](#11-keamanan--etika-penggunaan)
12. [Proyek Terkait](#12-proyek-terkait)
13. [Referensi](#13-referensi)

---

## 1. Apa Itu Alat Ini?

Ini adalah **alat command-line Python** untuk memverifikasi password terhadap hash `wallet.dat` milik Bitcoin Core dan Litecoin Core. Alat ini mengimplementasikan ulang algoritma kriptografi yang sama persis seperti yang digunakan Bitcoin Core (`src/wallet/crypter.cpp`), seluruhnya dalam Python, dengan opsi akselerasi GPU via OpenCL.

**Fungsi inti:** Diberikan hash dalam format HashCat `-m 11300` dan sebuah wordlist, alat ini memeriksa setiap kandidat password dan melaporkan jika ada yang cocok — tanpa perlu akses ke file `wallet.dat` asli.

**Hubungan dengan versi HTML:** Alat Python ini adalah pasangan command-line dari [Bitcoin-Hash-Wallet-Checker-HTML](https://github.com/syabiz/Bitcoin-Hash-Wallet-Checker-HTML) yang berbasis browser. Keduanya mengimplementasikan algoritma kriptografi yang identik. Versi Python cocok untuk wordlist besar dan alur kerja otomatis; versi HTML cocok untuk pemeriksaan hash tunggal yang cepat tanpa perlu instalasi apapun.

---

## 2. Kebutuhan & Instalasi

### Versi Python

Dibutuhkan Python **3.8 atau lebih tinggi**.

### Wajib (tidak perlu install tambahan)

Alat ini langsung berjalan hanya dengan pustaka standar Python. Semua primitif kriptografi (SHA-512, AES-256-CBC) memiliki implementasi pure-Python bawaan sebagai fallback.

### Opsional (direkomendasikan untuk performa lebih baik)

```bash
# AES cepat via ekstensi C (~10–50× lebih cepat dari pure Python)
pip install pycryptodome

# Akselerasi GPU via OpenCL (membutuhkan GPU kompatibel + driver)
pip install pyopencl numpy
```

> **Catatan untuk pengguna GPU:** Kamu juga perlu OpenCL runtime untuk GPU-mu:
> - NVIDIA: Install CUDA Toolkit atau driver GPU saja (sudah termasuk OpenCL)
> - AMD: Install ROCm atau driver AMD GPU
> - Intel: Install Intel oneAPI Base Toolkit

---

## 3. Cara Cepat Mulai

```bash
# 1. Clone repositori
git clone https://github.com/syabiz/Bitcoin-Hash-Wallet-Checker-Python.git
cd Bitcoin-Hash-Wallet-Checker-Python

# 2. (Opsional) Install AES cepat
pip install pycryptodome

# 3. Buat file input (lihat Bagian 4)
#    targets.txt  — satu hash per baris
#    wordlist.txt — satu password per baris

# 4. Jalankan (auto-deteksi GPU jika tersedia, fallback ke CPU)
python3 bitcoin_checker.py

# 5. Hasil disimpan ke results.txt
```

---

## 4. Format File Input

### `targets.txt` — File hash

Satu hash per baris. Baris yang diawali `#` dianggap komentar dan dilewati.

```
# targets.txt
$bitcoin$64$286ab85b3f33d80f954b8fdf272bf9884884499e783699e8d4c7c266c3fd6023$16$69e2890df94ce226$244252$2$00$2$00
$bitcoin$64$9618854225c49afded96d7f2562b078f685867e583865f0c85f794379849254b$16$6bb5d8031eaa5933$247325$2$00$2$00
```

Kedua prefix `$bitcoin$` dan `$litecoin$` didukung.

### `wordlist.txt` — Kandidat password

Satu password per baris. Baris kosong dilewati.

```
password
123456
bitcoin
wallet
2315
satoshi@bitcoin
crypto2024
Abc#123
Abc123
Abc@123
crypto123
1234567890
qwerty
abc123
```

> **Tips:** Kamu bisa menggunakan wordlist standar seperti `rockyou.txt`, atau membuat wordlist terarah dengan alat seperti `crunch`, `hashcat --stdout`, atau `CUPP`.

---

## 5. Cara Kerja — Algoritma

Alat ini mereplikasi enkripsi wallet Bitcoin Core seperti yang didefinisikan di `src/wallet/crypter.cpp`.

### Langkah 1 — Parsing hash

Hash menggunakan format HashCat `-m 11300`:

```
$bitcoin$<mkHexLen>$<mkHex>$<saltHexLen>$<saltHex>$<iterations>$...
```

| Field | Arti |
|---|---|
| `mkHexLen` | Panjang **string** mkHex (bukan jumlah byte!) |
| `mkHex` | Encrypted Master Key dalam hex |
| `saltHexLen` | Panjang **string** saltHex (bukan jumlah byte!) |
| `saltHex` | Salt dalam hex |
| `iterations` | Jumlah iterasi SHA-512 |

> ⚠️ **Penting:** `mkHexLen=64` artinya 64 karakter hex = 32 byte. Ini BUKAN jumlah byte yang dikalikan 2.

### Langkah 2 — Key Derivation (KDF)

Bitcoin Core menggunakan KDF SHA-512 iteratif:

```
Putaran 1:   hash = SHA-512(password_bytes + salt_bytes)
Putaran 2–N: hash = SHA-512(hash)

Output:
  key = hash[0..31]   (32 byte → kunci AES-256)
  iv  = hash[32..47]  (16 byte → IV AES-CBC)
```

### Langkah 3 — Dekripsi AES-256-CBC

Dekripsi 32 byte pertama dari `mkHex` menggunakan `key` dan `iv` yang sudah diturunkan.

### Langkah 4 — Validasi Padding

Master key Bitcoin selalu 32 byte (AES-256). PKCS7 padding pada 32 byte menghasilkan tepat satu blok padding penuh: **16 × `0x10`**.

```
✅ BENAR (password cocok):
   16 byte terakhir dari output dekripsi = [0x10, 0x10, 0x10, ..., 0x10]

❌ SALAH (password tidak cocok):
   16 byte terakhir = data acak
```

Pemeriksaan ketat (semua 16 byte harus sama dengan `0x10`) menghasilkan tingkat false-positive sekitar 1 per 256¹⁶ ≈ 0. Pemeriksaan longgar (`byte terakhir >= 1 dan <= 16`) menghasilkan ~6,25% false-positive.

---

## 6. Bug yang Diperbaiki & Catatan Teknis

Masalah-masalah berikut ditemukan dan diperbaiki selama pengembangan:

### Bug #1 — Salah interpretasi `mkHexLen` (Kritis)

**Kode asal (salah):**
```python
if len(master_hex) != mk_hex_len * 2:  # ← perkalian *2 ini salah!
```

**Kode yang diperbaiki:**
```python
if len(master_hex) != mk_hex_len:  # mkHexLen sudah berupa panjang string hex
```

`mkHexLen` adalah panjang string hex, bukan jumlah byte. Mengalikan dengan 2 menyebabkan semua hash dengan `mkHexLen=64` ditolak sebagai tidak valid.

### Bug #2 — Kernel GPU: batas satu blok SHA-512 (Menengah)

**Asli:** Implementasi SHA-512 di OpenCL hanya mendukung input hingga 111 byte (satu blok 128 byte). Ketika `password + salt` melebihi batas ini, hash yang dihasilkan diam-diam salah.

**Diperbaiki:** Kernel sekarang menangani SHA-512 dua blok untuk input hingga 239 byte. Dalam praktiknya, password dibatasi 63 byte dan salt Bitcoin adalah 8 byte (total ≤ 71 byte), sehingga ini adalah perbaikan defensif namun penting untuk kebenaran.

### Keputusan desain — Validasi PKCS7 ketat

Validasi memeriksa bahwa semua 16 byte trailing sama dengan `0x10`. Ini spesifik untuk Bitcoin: karena master key selalu 32 byte, padding-nya selalu tepat satu blok penuh `0x10`. Menggunakan pemeriksaan longgar akan menghasilkan false positive pada sekitar 1 dari 16 password yang salah.

---

## 7. Mode CPU vs GPU

| Aspek | Mode CPU | Mode GPU |
|---|---|---|
| Default | ✅ (auto-deteksi) | Hanya jika pyopencl terinstal |
| Paralelisme | `multiprocessing` Python (semua core) | OpenCL work-items (ratusan hingga ribuan) |
| Terbaik untuk | Wordlist kecil–menengah | Wordlist besar dengan GPU kompatibel |
| Dependensi | Tidak ada | `pyopencl`, `numpy`, driver GPU |
| Akurasi | ✅ Identik | ✅ Identik |

Kernel GPU mengimplementasikan algoritma lengkap dalam OpenCL C: KDF SHA-512 iteratif + AES-256-CBC + validasi PKCS7 ketat. Hasilnya identik secara numerik dengan jalur CPU.

---

## 8. Referensi Argumen CLI

```
python3 bitcoin_checker.py [OPTIONS]
```

| Opsi | Default | Keterangan |
|---|---|---|
| `--targets FILE` | `targets.txt` | File hash (satu hash `$bitcoin$` per baris) |
| `--wordlist FILE` | `wordlist.txt` | Wordlist password |
| `--output FILE` | `results.txt` | File output untuk hasil |
| `--mode MODE` | `auto` | `auto`, `cpu`, atau `gpu` |
| `--workers N` | Jumlah CPU | Jumlah worker CPU (hanya mode CPU) |
| `--gpu-batch N` | `512` | Password per dispatch GPU (hanya mode GPU) |
| `--csv` | mati | Simpan juga hasil sebagai CSV |
| `--no-color` | mati | Nonaktifkan warna ANSI di output |

### Contoh penggunaan

```bash
# Mode otomatis (gunakan GPU jika ada, kalau tidak pakai CPU)
python3 bitcoin_checker.py

# Paksa CPU dengan 8 worker
python3 bitcoin_checker.py --mode cpu --workers 8

# Paksa GPU dengan batch lebih besar
python3 bitcoin_checker.py --mode gpu --gpu-batch 1024

# File kustom dan output CSV
python3 bitcoin_checker.py --targets hash_saya.txt --wordlist rockyou.txt --output ditemukan.txt --csv

# Nonaktifkan warna (untuk file log / CI)
python3 bitcoin_checker.py --no-color
```

---

## 9. Format Output

### Terminal (progress langsung)

```
  ₿  Bitcoin / Litecoin wallet.dat  —  Batch Password Checker
  SHA-512 Iterative · AES-256-CBC · Strict PKCS7 (0x10 × 16)

  Dependensi:
    AES       : pycryptodome
    GPU/OpenCL: tidak ada → pip install pyopencl numpy
    CPU cores : 8

  Input:
  Hashes  : 2 valid (0 dilewati)  ← targets.txt
  Wordlist: 14344392 password     ← wordlist.txt

  Mode     : CPU  (workers=8)
  Total ops: 28.688.784  (2 hash × 14344392 password)
  Output   : results.txt

  [████████████░░░░░░░░░░░░░░░░░░]  41,2%  ✓1  11.822.001/28.688.784  847,3/s  ETA 19,8m

  ✓ FOUND  Hash #1  →  'correct horse battery staple'
```

### `results.txt`

```
# Bitcoin Batch Checker — Results
# Time     : 2026-02-22 22:54:25
# Found    : 2 / 2

[FOUND] $bitcoin$64$286ab85b3f33d80f954b8fdf272bf9884884499e783699e8d4c7c266c3fd6023$16$69e2890df94ce226$244252$2$00$2$00
         Password  : Abc#123
         Iterations: 244252
         Time      : 26.38s

[FOUND] $bitcoin$64$9618854225c49afded96d7f2562b078f685867e583865f0c85f794379849254b$16$6bb5d8031eaa5933$247325$2$00$2$00
         Password  : satoshi@bitcoin
         Iterations: 247325
         Time      : 26.71s
```

### `results.csv` (dengan `--csv`)

```csv
status,password,iterations,time_s,hash
found,correct horse battery staple,35714,483.210,"$bitcoin$64$..."
not_found,,25000,612.430,"$litecoin$64$..."
```

---

## 10. Mengekstrak Hash dari wallet.dat

### Menggunakan bitcoin2john.py (dari John the Ripper)

```bash
pip install bsddb3

python bitcoin2john.py /path/ke/wallet.dat
# Output: wallet.dat:$bitcoin$64$xxxxx$16$xxxxx$25000$2$00$2$00
```

Salin semua yang ada setelah tanda `:` dan tempel ke `targets.txt`.

### Catatan tentang format hash

Hash berisi master key terenkripsi, bukan private key secara langsung. Memecahkan hash mengungkapkan password wallet, yang kemudian digunakan Bitcoin Core untuk mendekripsi semua private key yang tersimpan di dalam wallet.

---

## 11. Keamanan & Etika Penggunaan

### ✅ Penggunaan yang diizinkan

- Memverifikasi password `wallet.dat` milik kamu sendiri
- Forensik digital di bawah kewenangan hukum dengan otorisasi yang tepat
- Riset dan edukasi kriptografi
- Audit keamanan dengan izin tertulis dari pemilik wallet

### ❌ Penggunaan yang dilarang

- Mengakses wallet yang bukan milikmu
- Segala bentuk pencurian cryptocurrency
- Akses tidak sah ke dana orang lain

### Privasi

Alat ini berjalan sepenuhnya secara lokal. Tidak ada data (hash, password, hasil) yang dikirim ke mana pun. Semua komputasi terjadi di mesinmu sendiri.

---

## 12. Proyek Terkait

| Proyek | Keterangan |
|---|---|
| [Bitcoin-Hash-Wallet-Checker-HTML](https://github.com/syabiz/Bitcoin-Hash-Wallet-Checker-HTML) | Versi berbasis browser — tidak perlu install, cek tunggal + batch |
| [bitcoin2john.py](https://github.com/openwall/john) | Mengekstrak hash `$bitcoin$` dari `wallet.dat` |
| [hashcat -m 11300](https://hashcat.net) | Pemecah hash dengan akselerasi GPU (referensi format hash) |

---

## 13. Referensi

| Sumber | Keterangan |
|---|---|
| `src/wallet/crypter.cpp` (Bitcoin Core) | Implementasi KDF dan enkripsi wallet yang otoritatif |
| RFC 2898 | PKCS #5: Spesifikasi Kriptografi Berbasis Password |
| FIPS 197 | Advanced Encryption Standard (AES) |
| RFC 2315 | PKCS #7: Cryptographic Message Syntax |
| FIPS 180-4 | Secure Hash Standard (SHA-512) |

---

## Donasi

Jika alat ini bermanfaat untuk pekerjaanmu atau belajarmu, donasi sangat diapresiasi:

- **Bitcoin (BTC)** — `bc1qn6t8hy8memjfzp4y3sh6fvadjdtqj64vfvlx58`
- **Ethereum (ETH)** — `0x512936ca43829C8f71017aE47460820Fe703CAea`
- **Solana (SOL)** — `6ZZrRmeGWMZSmBnQFWXG2UJauqbEgZnwb4Ly9vLYr7mi`
- **PayPal** — syabiz@yandex.com

Donasi akan digunakan untuk pengembangan fitur baru, pemeliharaan, dan dokumentasi.

---

## Kontak

- **GitHub Issues:** https://github.com/syabiz/Bitcoin-Hash-Wallet-Checker-Python/issues
- **Email:** syabiz@yandex.com
- **Twitter:** @syabiz

---

*Dibuat untuk tujuan edukasi. Gunakan dengan bertanggung jawab.*  
*Lisensi MIT — lihat file LICENSE*  
*Terakhir diperbarui: Februari 2026*
