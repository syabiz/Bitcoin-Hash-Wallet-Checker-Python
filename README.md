# 🐍 Bitcoin / Litecoin wallet.dat — Batch Password Checker (Python)

> **Educational Tool** · Python 3 · CPU & GPU  
> For: cryptography students, digital forensics teams, blockchain developers

---

## 📋 Table of Contents

1. [What Is This Tool?](#1-what-is-this-tool)
2. [Requirements & Installation](#2-requirements--installation)
3. [Quick Start](#3-quick-start)
4. [Input File Formats](#4-input-file-formats)
5. [How It Works — Algorithm](#5-how-it-works--algorithm)
6. [Bug Fixes & Technical Notes](#6-bug-fixes--technical-notes)
7. [CPU vs GPU Mode](#7-cpu-vs-gpu-mode)
8. [Command-Line Reference](#8-command-line-reference)
9. [Output Format](#9-output-format)
10. [Extracting a Hash from wallet.dat](#10-extracting-a-hash-from-walletdat)
11. [Security & Ethical Use](#11-security--ethical-use)
12. [Related Projects](#12-related-projects)
13. [References](#13-references)

---

## 1. What Is This Tool?

This is a **Python command-line tool** for verifying passwords against Bitcoin Core and Litecoin Core `wallet.dat` hashes. It reimplements the same cryptographic algorithm used by Bitcoin Core (`src/wallet/crypter.cpp`) entirely in Python, with an optional GPU acceleration path via OpenCL.

**Core function:** Given a hash in HashCat `-m 11300` format and a wordlist, the tool checks each password candidate and reports any match — without needing access to the original `wallet.dat` file.

**Relationship to the HTML version:** This Python tool is the command-line counterpart to the browser-based [Bitcoin-Hash-Wallet-Checker-HTML](https://github.com/syabiz/Bitcoin-Hash-Wallet-Checker-HTML). Both implement the identical cryptographic algorithm. The Python version is suitable for large wordlists and automated workflows; the HTML version is suitable for quick single-hash checks without installing anything.

---

## 2. Requirements & Installation

### Python version

Python **3.8 or higher** is required.

### Mandatory (no additional install needed)

The tool works out-of-the-box with only Python's standard library. All cryptographic primitives (SHA-512, AES-256-CBC) have a pure-Python fallback implementation built in.

### Optional (recommended for better performance)

```bash
# Fast AES via C extension (~10–50× faster than pure Python)
pip install pycryptodome

# GPU acceleration via OpenCL (requires compatible GPU + drivers)
pip install pyopencl numpy
```

> **Note for GPU users:** You also need the OpenCL runtime for your GPU:
> - NVIDIA: Install CUDA Toolkit or just the GPU driver (includes OpenCL)
> - AMD: Install ROCm or AMD GPU drivers
> - Intel: Install Intel oneAPI Base Toolkit

---

## 3. Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/syabiz/Bitcoin-Hash-Wallet-Checker-Python.git
cd Bitcoin-Hash-Wallet-Checker-Python

# 2. (Optional) Install fast AES
pip install pycryptodome

# 3. Create your input files (see Section 4)
#    targets.txt  — one hash per line
#    wordlist.txt — one password per line

# 4. Run (auto-detects GPU if available, falls back to CPU)
python3 bitcoin_checker.py

# 5. Results are saved to results.txt
```

---

## 4. Input File Formats

### `targets.txt` — Hash file

One hash per line. Lines starting with `#` are treated as comments and skipped.

```
# targets.txt
$bitcoin$64$617c4b22fabd578e0f4d030245a0cbebd9da426fbee49c2feb885fa190b65096$16$dff2b89e4d885c28$35714$2$00$2$00
$litecoin$64$abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890$16$1234567890abcdef$25000$2$00$2$00
```

Both `$bitcoin$` and `$litecoin$` prefixes are supported.

### `wordlist.txt` — Password candidates

One password per line. Empty lines are skipped.

```
password
123456
mybitcoin2009
correct horse battery staple
```

> **Tip:** You can use standard wordlists like `rockyou.txt`, or generate targeted wordlists with tools like `crunch`, `hashcat --stdout`, or `CUPP`.

---

## 5. How It Works — Algorithm

The tool replicates Bitcoin Core's wallet encryption as defined in `src/wallet/crypter.cpp`.

### Step 1 — Parse the hash

The hash is in HashCat `-m 11300` format:

```
$bitcoin$<mkHexLen>$<mkHex>$<saltHexLen>$<saltHex>$<iterations>$...
```

| Field | Meaning |
|---|---|
| `mkHexLen` | Length of the mkHex **string** (not byte count!) |
| `mkHex` | Encrypted Master Key in hex |
| `saltHexLen` | Length of the saltHex **string** (not byte count!) |
| `saltHex` | Salt in hex |
| `iterations` | Number of SHA-512 iterations |

> ⚠️ **Critical:** `mkHexLen=64` means 64 hex characters = 32 bytes. It is NOT a byte count multiplied by 2.

### Step 2 — Key Derivation (KDF)

Bitcoin Core uses an iterative SHA-512 KDF:

```
Round 1:   hash = SHA-512(password_bytes + salt_bytes)
Round 2–N: hash = SHA-512(hash)

Output:
  key = hash[0..31]   (32 bytes → AES-256 key)
  iv  = hash[32..47]  (16 bytes → AES-CBC IV)
```

### Step 3 — AES-256-CBC Decryption

Decrypt the first 32 bytes of `mkHex` using the derived `key` and `iv`.

### Step 4 — Padding Validation

The Bitcoin master key is always 32 bytes (AES-256). PKCS7 padding on 32 bytes produces exactly one full block of padding: **16 × `0x10`**.

```
✅ CORRECT (password matches):
   last 16 bytes of decrypted output = [0x10, 0x10, 0x10, ..., 0x10]

❌ WRONG (password does not match):
   last 16 bytes = random-looking data
```

The strict check (all 16 bytes must equal `0x10`) gives a false-positive rate of approximately 1 in 256¹⁶ ≈ 0. A lenient check (`last byte >= 1 and <= 16`) would give ~6.25% false positives.

---

## 6. Bug Fixes & Technical Notes

The following issues were identified and corrected during development:

### Bug #1 — `mkHexLen` misinterpretation (Critical)

**Original code (wrong):**
```python
if len(master_hex) != mk_hex_len * 2:  # ← the *2 is wrong!
```

**Fixed code:**
```python
if len(master_hex) != mk_hex_len:  # mkHexLen is already hex string length
```

`mkHexLen` is the length of the hex string, not the byte count. Multiplying by 2 caused all hashes with `mkHexLen=64` to be rejected as invalid.

### Bug #2 — GPU kernel: SHA-512 single-block limit (Medium)

**Original:** The OpenCL SHA-512 implementation only supported inputs up to 111 bytes (one 128-byte block). When `password + salt` exceeded this limit, the hash was silently wrong.

**Fixed:** The kernel now handles two-block SHA-512 for inputs up to 239 bytes. In practice, passwords are capped at 63 bytes and Bitcoin's salt is 8 bytes (total ≤ 71 bytes), so this is a defensive fix but important for correctness.

### Design decision — Strict PKCS7 validation

The validation checks that all 16 trailing bytes equal `0x10`. This is Bitcoin-specific: because the master key is always 32 bytes, the padding is always exactly one full block of `0x10`. Using a lenient check would produce false positives on approximately 1 in 16 wrong passwords.

---

## 7. CPU vs GPU Mode

| Aspect | CPU mode | GPU mode |
|---|---|---|
| Default | ✅ (auto-detected) | Only if pyopencl is installed |
| Parallelism | Python `multiprocessing` (all cores) | OpenCL work-items (hundreds to thousands) |
| Best for | Small–medium wordlists | Large wordlists with a compatible GPU |
| Dependencies | None | `pyopencl`, `numpy`, GPU drivers |
| Accuracy | ✅ Identical | ✅ Identical |

The GPU kernel implements the full algorithm in OpenCL C: SHA-512 iterative KDF + AES-256-CBC + strict PKCS7 validation. Results are numerically identical to the CPU path.

---

## 8. Command-Line Reference

```
python3 bitcoin_checker.py [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--targets FILE` | `targets.txt` | Hash file (one `$bitcoin$` hash per line) |
| `--wordlist FILE` | `wordlist.txt` | Password wordlist |
| `--output FILE` | `results.txt` | Output file for results |
| `--mode MODE` | `auto` | `auto`, `cpu`, or `gpu` |
| `--workers N` | CPU count | Number of CPU workers (CPU mode only) |
| `--gpu-batch N` | `512` | Passwords per GPU dispatch (GPU mode only) |
| `--csv` | off | Also save results as CSV |
| `--no-color` | off | Disable ANSI color output |

### Examples

```bash
# Auto mode (uses GPU if available, else CPU)
python3 bitcoin_checker.py

# Force CPU with 8 workers
python3 bitcoin_checker.py --mode cpu --workers 8

# Force GPU with larger batch
python3 bitcoin_checker.py --mode gpu --gpu-batch 1024

# Custom files and CSV output
python3 bitcoin_checker.py --targets my_hashes.txt --wordlist rockyou.txt --output found.txt --csv

# Disable colors (for log files / CI)
python3 bitcoin_checker.py --no-color
```

---

## 9. Output Format

### Terminal (live progress)

```
  ₿  Bitcoin / Litecoin wallet.dat  —  Batch Password Checker
  SHA-512 Iterative · AES-256-CBC · Strict PKCS7 (0x10 × 16)

  Dependencies:
    AES       : pycryptodome
    GPU/OpenCL: not found → pip install pyopencl numpy
    CPU cores : 8

  Input:
  Hashes  : 2 valid (0 skipped)  ← targets.txt
  Wordlist: 14344392 passwords   ← wordlist.txt

  Mode     : CPU  (workers=8)
  Total ops: 28,688,784  (2 hashes × 14344392 passwords)
  Output   : results.txt

  [████████████░░░░░░░░░░░░░░░░░░]  41.2%  ✓1  11,822,001/28,688,784  847.3/s  ETA 19.8m

  ✓ FOUND  Hash #1  →  'correct horse battery staple'
```

### `results.txt`

```
# Bitcoin Batch Checker — Results
# Time     : 2026-02-22 14:33:01
# Found    : 1 / 2

[FOUND] $bitcoin$64$617c4b22...
         Password  : correct horse battery staple
         Iterations: 35714
         Time      : 483.21s

[NOT_FOUND] $bitcoin$64$abcdef12...
```

### `results.csv` (with `--csv`)

```csv
status,password,iterations,time_s,hash
found,correct horse battery staple,35714,483.210,"$bitcoin$64$..."
not_found,,25000,612.430,"$litecoin$64$..."
```

---

## 10. Extracting a Hash from wallet.dat

### Using bitcoin2john.py (from John the Ripper)

```bash
pip install bsddb3

python bitcoin2john.py /path/to/wallet.dat
# Output: wallet.dat:$bitcoin$64$xxxxx$16$xxxxx$25000$2$00$2$00
```

Copy everything after the `:` and paste it into `targets.txt`.

### Notes on the hash format

The hash contains the encrypted master key, not the private key directly. Cracking the hash reveals the wallet password, which Bitcoin Core then uses to decrypt all private keys stored inside the wallet.

---

## 11. Security & Ethical Use

### ✅ Permitted use

- Verifying the password of your own `wallet.dat`
- Digital forensics under lawful authority with proper authorization
- Cryptography research and education
- Security audits with written permission from the wallet owner

### ❌ Prohibited use

- Accessing wallets that do not belong to you
- Any form of cryptocurrency theft
- Unauthorized access to other people's funds

### Privacy

This tool runs entirely locally. No data (hashes, passwords, results) is sent anywhere. All computation happens on your own machine.

---

## 12. Related Projects

| Project | Description |
|---|---|
| [Bitcoin-Hash-Wallet-Checker-HTML](https://github.com/syabiz/Bitcoin-Hash-Wallet-Checker-HTML) | Browser-based version — no install required, single + batch check |
| [bitcoin2john.py](https://github.com/openwall/john) | Extracts `$bitcoin$` hash from `wallet.dat` |
| [hashcat -m 11300](https://hashcat.net) | GPU-accelerated hash cracker (reference for hash format) |

---

## 13. References

| Source | Description |
|---|---|
| `src/wallet/crypter.cpp` (Bitcoin Core) | Authoritative KDF and wallet encryption implementation |
| RFC 2898 | PKCS #5: Password-Based Cryptography Specification |
| FIPS 197 | Advanced Encryption Standard (AES) |
| RFC 2315 | PKCS #7: Cryptographic Message Syntax |
| FIPS 180-4 | Secure Hash Standard (SHA-512) |

---

## Donation

If this tool has been useful for your work or learning, donations are appreciated:

- **Bitcoin (BTC)** — `bc1qn6t8hy8memjfzp4y3sh6fvadjdtqj64vfvlx58`
- **Ethereum (ETH)** — `0x512936ca43829C8f71017aE47460820Fe703CAea`
- **Solana (SOL)** — `6ZZrRmeGWMZSmBnQFWXG2UJauqbEgZnwb4Ly9vLYr7mi`
- **PayPal** — syabiz@yandex.com

---

## Contact

- **GitHub Issues:** https://github.com/syabiz/Bitcoin-Hash-Wallet-Checker-Python/issues
- **Email:** syabiz@yandex.com
- **Twitter:** @syabiz

---

*Created for educational purposes. Use responsibly.*  
*MIT License — see LICENSE file*  
*Last updated: February 2026*
