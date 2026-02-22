#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        Bitcoin / Litecoin wallet.dat  —  Batch Password Checker              ║
║                                                                              ║
║  Mode CPU : multiprocessing (all cores)                                      ║
║  Mode GPU : OpenCL  (NVIDIA / AMD / Intel GPU)                               ║
║  KDF      : SHA-512 Iterative  (Bitcoin Core  src/wallet/crypter.cpp)        ║
║  Crypto   : AES-256-CBC                                                      ║
║  Validate : Strict PKCS7 — last 16 bytes must all be 0x10                   ║
║                                                                              ║
║  Input  :  targets.txt   — one hash per line                                 ║
║            wordlist.txt  — one password per line                             ║
║  Output :  results.txt   — saved automatically                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

INSTALL:
    pip install pycryptodome        # fast AES (C-extension, strongly recommended)
    pip install pyopencl numpy      # GPU mode (optional)

USAGE:
    python3 bitcoin_checker.py
    python3 bitcoin_checker.py --mode gpu
    python3 bitcoin_checker.py --mode cpu --workers 8
    python3 bitcoin_checker.py --targets targets.txt --wordlist wordlist.txt
    python3 bitcoin_checker.py --output found.txt --csv

SAMPLE HASHES (for testing — use loadSampleHashes in HTML version to match):
    # password: satoshi    (10 iterations)
    $bitcoin$64$2d06d1d9ceb5ae458c8aab81ec24663c068c5fd65ea7d4ce64601cc24ac53937$16$aabbccdd11223344$10$2$00$2$00
    # password: bitcoin2024 (5 iterations)
    $bitcoin$64$498edd71e2c12eb9ae44c3258ad9dedb029c64f0c54bfb3c122a241ed65996d1$16$deadbeef12345678$5$2$00$2$00
    # password: 1234567890  (8 iterations)
    $bitcoin$64$f26bba995787586566a3417bfb94cbaa785b8d4f5cfe5708508708c0842a6a69$16$fedcba9876543210$8$2$00$2$00
"""

import argparse
import hashlib
import multiprocessing
import os
import sys
import time
from datetime import datetime
from threading import Lock

# ── Optional dependencies ─────────────────────────────────────────────────────
HAS_PYCRYPTO = False
HAS_OPENCL   = False

try:
    from Crypto.Cipher import AES as _FastAES
    HAS_PYCRYPTO = True
except ImportError:
    pass

try:
    import pyopencl as cl
    import numpy as np
    HAS_OPENCL = True
except ImportError:
    pass


# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLOR
# ─────────────────────────────────────────────────────────────────────────────
_COLOR = sys.stdout.isatty()

def _c(code, s): return f"\033[{code}m{s}\033[0m" if _COLOR else s
def green(s):  return _c("92", s)
def red(s):    return _c("91", s)
def yellow(s): return _c("93", s)
def cyan(s):   return _c("96", s)
def bold(s):   return _c("1",  s)
def dim(s):    return _c("2",  s)
def orange(s): return _c("33", s)


# ─────────────────────────────────────────────────────────────────────────────
# PURE PYTHON AES-256-CBC  (verified against NIST FIPS 197 & SP 800-38A vectors)
#
# BUG FIX (critical): The original implementation had a key schedule bug.
# Round keys were built with inconsistent row/column ordering, causing every
# decryption to produce garbage output regardless of whether the password
# was correct. This caused ALL passwords to fail, even correct ones.
#
# Fix: use consistent column-major (FIPS 197) state layout throughout:
#   state[col*4 + row]  for all operations
#
# Verified against:
#   NIST FIPS 197 Appendix B (AES-256 ECB)
#   NIST SP 800-38A Section F.2 (AES-256 CBC)
# ─────────────────────────────────────────────────────────────────────────────

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _aes256_key_expand(key: bytes) -> list:
    """
    AES-256 key schedule → 15 round keys.
    State layout: column-major  →  flat[col*4 + row]
    This matches FIPS 197 and is consistent with all AES operations below.
    """
    # Build 60 words (4 bytes each) from the 32-byte key
    w = [list(key[i*4:(i+1)*4]) for i in range(8)]
    for i in range(8, 60):
        t = w[i-1][:]
        if i % 8 == 0:
            # RotWord + SubWord + XOR Rcon
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // 8 - 1]
        elif i % 8 == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i-8][j] ^ t[j] for j in range(4)])

    # Build round keys in column-major order: flat[col*4 + row]
    rk = []
    for r in range(15):
        flat = []
        for col in range(4):
            for row in range(4):
                flat.append(w[r*4 + col][row])
        rk.append(flat)
    return rk


def _inv_shift_rows(s: list) -> list:
    r = s[:]
    # Row 1: shift right 1
    r[1],  r[5],  r[9],  r[13] = s[13], s[1],  s[5],  s[9]
    # Row 2: shift right 2
    r[2],  r[6],  r[10], r[14] = s[10], s[14], s[2],  s[6]
    # Row 3: shift right 3
    r[3],  r[7],  r[11], r[15] = s[7],  s[11], s[15], s[3]
    return r


def _inv_mix_columns(s: list) -> list:
    out = [0] * 16
    for c in range(4):
        s0, s1, s2, s3 = s[c*4], s[c*4+1], s[c*4+2], s[c*4+3]
        out[c*4]   = _gmul(s0,0xe)^_gmul(s1,0xb)^_gmul(s2,0xd)^_gmul(s3,0x9)
        out[c*4+1] = _gmul(s0,0x9)^_gmul(s1,0xe)^_gmul(s2,0xb)^_gmul(s3,0xd)
        out[c*4+2] = _gmul(s0,0xd)^_gmul(s1,0x9)^_gmul(s2,0xe)^_gmul(s3,0xb)
        out[c*4+3] = _gmul(s0,0xb)^_gmul(s1,0xd)^_gmul(s2,0x9)^_gmul(s3,0xe)
    return out


def _aes256_decrypt_block(block: bytes, rk: list) -> bytes:
    """AES-256 single-block decryption. State in column-major order."""
    s = list(block)
    s = [s[i] ^ rk[14][i] for i in range(16)]
    for r in range(13, 0, -1):
        s = _inv_shift_rows(s)
        s = [_INV_SBOX[b] for b in s]
        s = [s[i] ^ rk[r][i] for i in range(16)]
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = [_INV_SBOX[b] for b in s]
    s = [s[i] ^ rk[0][i] for i in range(16)]
    return bytes(s)


def aes256_cbc_decrypt_nopad(key: bytes, iv: bytes, ct: bytes) -> bytes:
    """AES-256-CBC decrypt without padding removal."""
    if HAS_PYCRYPTO:
        return _FastAES.new(key, _FastAES.MODE_CBC, iv).decrypt(ct)
    # Pure Python fallback (NIST-verified)
    rk   = _aes256_key_expand(key)
    out  = bytearray()
    prev = list(iv)
    for i in range(0, len(ct), 16):
        blk  = ct[i:i+16]
        dec  = _aes256_decrypt_block(blk, rk)
        out += bytes(x ^ y for x, y in zip(dec, prev))
        prev = list(blk)
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────────────
# HASH PARSER
# ─────────────────────────────────────────────────────────────────────────────
class ParseError(ValueError):
    pass


def parse_hash(line: str) -> dict:
    """
    HashCat format -m 11300:
      $bitcoin$<mkHexLen>$<mkHex>$<saltHexLen>$<saltHex>$<iterations>$...

    mkHexLen = length of the HEX STRING (not byte count!).
      mkHexLen=64 → 64 hex chars = 32 bytes.
    """
    h = line.strip()
    if   h.startswith("$bitcoin$"):  prefix = "$bitcoin$"
    elif h.startswith("$litecoin$"): prefix = "$litecoin$"
    else:
        raise ParseError(f"Not $bitcoin$/$litecoin$: {h[:40]}")

    parts = h[len(prefix):].split("$")
    if len(parts) < 5:
        raise ParseError(f"Incomplete hash ({len(parts)} parts, need ≥5)")

    try:
        mk_hex_len   = int(parts[0])
        master_hex   = parts[1]
        salt_hex_len = int(parts[2])
        salt_hex     = parts[3]
        iterations   = int(parts[4])
    except ValueError as e:
        raise ParseError(f"Non-numeric field: {e}")

    # mkHexLen is the hex string length, NOT byte count (no *2 needed)
    if len(master_hex) != mk_hex_len:
        raise ParseError(
            f"mkHex length {len(master_hex)}, expected {mk_hex_len} "
            f"(mkHexLen = hex string length, not bytes)"
        )
    if len(salt_hex) != salt_hex_len:
        raise ParseError(
            f"saltHex length {len(salt_hex)}, expected {salt_hex_len}"
        )
    if len(master_hex) < 32:
        raise ParseError(f"mkHex too short ({len(master_hex)} chars), min 32")
    if not (1 <= iterations <= 50_000_000):
        raise ParseError(f"Unusual iteration count: {iterations}")

    return {
        "raw":          h,
        "master_bytes": bytes.fromhex(master_hex),
        "salt_bytes":   bytes.fromhex(salt_hex),
        "iterations":   iterations,
    }


# ─────────────────────────────────────────────────────────────────────────────
# KDF  —  SHA-512 ITERATIVE  (Bitcoin Core crypter.cpp)
# Identical logic to HTML version's deriveKeyBitcoinSHA512()
# ─────────────────────────────────────────────────────────────────────────────
def derive_key(password: str, salt: bytes, iterations: int):
    """
    Round 1:   hash = SHA-512(password_bytes + salt_bytes)
    Round 2–N: hash = SHA-512(hash)
    Returns:   key = hash[0..31], iv = hash[32..47]
    """
    data = password.encode("utf-8") + salt
    h    = hashlib.sha512(data).digest()
    for _ in range(iterations - 1):
        h = hashlib.sha512(h).digest()
    return h[:32], h[32:48]


# ─────────────────────────────────────────────────────────────────────────────
# PADDING VALIDATION  —  STRICT BITCOIN-SPECIFIC
# Identical logic to HTML version's isValid check
# ─────────────────────────────────────────────────────────────────────────────
def valid_padding(dec: bytes) -> bool:
    """
    Bitcoin master key fits in ≤32 bytes. With PKCS7, the last block of the
    decrypted ciphertext is always all-0x10 (16 bytes of value 16).

    Lenient check (last >= 1 && last <= 16) → ~6.25% false positive rate.
    This strict check → false positive ~1/(256^16) ≈ 0.
    """
    if len(dec) < 16:
        return False
    last = dec[-1]
    if last != 0x10:
        return False
    return all(b == 0x10 for b in dec[-16:])


# ─────────────────────────────────────────────────────────────────────────────
# CHECK ONE (hash, password) PAIR
# ─────────────────────────────────────────────────────────────────────────────
def check_one(parsed: dict, password: str) -> bool:
    try:
        key, iv = derive_key(password, parsed["salt_bytes"], parsed["iterations"])
        # Decrypt the first 32 bytes of the encrypted master key
        ct  = parsed["master_bytes"][:32]
        dec = aes256_cbc_decrypt_nopad(key, iv, ct)
        return valid_padding(dec)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CPU WORKER  (subprocess via multiprocessing.Pool)
# ─────────────────────────────────────────────────────────────────────────────
def _worker(args):
    """Pool.imap worker: args = (hash_idx, parsed, password)"""
    h_idx, parsed, password = args
    return h_idx, password, check_one(parsed, password)


# ─────────────────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ─────────────────────────────────────────────────────────────────────────────
class Progress:
    def __init__(self, total: int):
        self.total   = total
        self.checked = 0
        self.found   = 0
        self.t0      = time.time()
        self._lock   = Lock()
        self._last   = 0.0

    def tick(self, found=False):
        with self._lock:
            self.checked += 1
            if found:
                self.found += 1

    def _rate(self):
        e = time.time() - self.t0
        return self.checked / e if e > 0 else 0.0

    def _eta(self):
        r = self._rate()
        if r <= 0: return "∞"
        s = (self.total - self.checked) / r
        if s < 60:    return f"{s:.0f}s"
        if s < 3600:  return f"{s/60:.1f}m"
        return f"{s/3600:.1f}h"

    def display(self, force=False):
        now = time.time()
        if not force and now - self._last < 0.4:
            return
        self._last = now
        pct    = min(100.0, self.checked / self.total * 100) if self.total else 0
        filled = int(30 * pct / 100)
        bar    = "█" * filled + "░" * (30 - filled)
        sys.stdout.write(
            f"\r  [{bar}] {pct:5.1f}%  "
            f"{green('✓'+str(self.found))}  "
            f"{cyan(str(self.checked))}/{self.total}  "
            f"{yellow(f'{self._rate():.1f}/s')}  "
            f"ETA {dim(self._eta())}   "
        )
        sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────────────────
# CPU MODE  —  multiprocessing Pool
# ─────────────────────────────────────────────────────────────────────────────
def run_cpu(hashes: list, words: list, workers: int) -> list:
    results   = {i: {"hash": h["raw"], "status": "not_found",
                     "iterations": h["iterations"], "time_s": 0.0,
                     "_t0": time.time()}
                 for i, h in enumerate(hashes)}
    found_set = set()
    total     = len(hashes) * len(words)
    prog      = Progress(total)

    def gen_tasks():
        for i, parsed in enumerate(hashes):
            for pw in words:
                if i not in found_set:
                    yield (i, parsed, pw)

    with multiprocessing.Pool(processes=workers) as pool:
        for h_idx, pw, found in pool.imap_unordered(
                _worker, gen_tasks(), chunksize=32):
            prog.tick(found=found)
            prog.display()
            if found and h_idx not in found_set:
                found_set.add(h_idx)
                results[h_idx].update({
                    "status":   "found",
                    "password": pw,
                    "time_s":   time.time() - results[h_idx]["_t0"],
                })
                prog.display(force=True)
                print(f"\n  {green('✓ FOUND')}  "
                      f"Hash #{h_idx+1}  →  {bold(green(repr(pw)))}")

    prog.display(force=True)
    print()
    return list(results.values())


# ─────────────────────────────────────────────────────────────────────────────
# OPENCL KERNEL SOURCE
# ─────────────────────────────────────────────────────────────────────────────
_OPENCL_SRC = r"""
/* ─── SHA-512 ─────────────────────────────────────────────────────────────── */
#define ROR64(x,n) (((ulong)(x)>>(n))|((ulong)(x)<<(64-(n))))

__constant ulong SHA512_K[80] = {
    0x428a2f98d728ae22UL,0x7137449123ef65cdUL,0xb5c0fbcfec4d3b2fUL,0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL,0x59f111f1b605d019UL,0x923f82a4af194f9bUL,0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL,0x12835b0145706fbeUL,0x243185be4ee4b28cUL,0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL,0x80deb1fe3b1696b1UL,0x9bdc06a725c71235UL,0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL,0xefbe4786384f25e3UL,0x0fc19dc68b8cd5b5UL,0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL,0x4a7484aa6ea6e483UL,0x5cb0a9dcbd41fbd4UL,0x76f988da831153b5UL,
    0x983e5152ee66dfabUL,0xa831c66d2db43210UL,0xb00327c898fb213fUL,0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL,0xd5a79147930aa725UL,0x06ca6351e003826fUL,0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL,0x2e1b21385c26c926UL,0x4d2c6dfc5ac42aedUL,0x53380d139d95b3dfUL,
    0x650a73548baf63deUL,0x766a0abb3c77b2a8UL,0x81c2c92e47edaee6UL,0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL,0xa81a664bbc423001UL,0xc24b8b70d0f89791UL,0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL,0xd69906245565a910UL,0xf40e35855771202aUL,0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL,0x1e376c085141ab53UL,0x2748774cdf8eeb99UL,0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL,0x4ed8aa4ae3418acbUL,0x5b9cca4f7763e373UL,0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL,0x78a5636f43172f60UL,0x84c87814a1f0ab72UL,0x8cc702081a6439ecUL,
    0x90befffa23631e28UL,0xa4506cebde82bde9UL,0xbef9a3f7b2c67915UL,0xc67178f2e372532bUL,
    0xca273eceea26619cUL,0xd186b8c721c0c207UL,0xeada7dd6cde0eb1eUL,0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL,0x0a637dc5a2c898a6UL,0x113f9804bef90daeUL,0x1b710b35131c471bUL,
    0x28db77f523047d84UL,0x32caab7b40c72493UL,0x3c9ebe0a15c9bebcUL,0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL,0x597f299cfc657e2aUL,0x5fcb6fab3ad6faecUL,0x6c44198c4a475817UL,
};

void sha512_compress(ulong st[8], const ulong blk[16]) {
    ulong w[80]; int i;
    for(i=0;i<16;i++) w[i]=blk[i];
    for(i=16;i<80;i++){
        ulong s0=ROR64(w[i-15],1)^ROR64(w[i-15],8)^(w[i-15]>>7);
        ulong s1=ROR64(w[i-2],19)^ROR64(w[i-2],61)^(w[i-2]>>6);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    ulong a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
    for(i=0;i<80;i++){
        ulong S1=ROR64(e,14)^ROR64(e,18)^ROR64(e,41);
        ulong ch=(e&f)^((~e)&g);
        ulong t1=h+S1+ch+SHA512_K[i]+w[i];
        ulong S0=ROR64(a,28)^ROR64(a,34)^ROR64(a,39);
        ulong mj=(a&b)^(a&c)^(b&c);
        ulong t2=S0+mj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;
    st[4]+=e;st[5]+=f;st[6]+=g;st[7]+=h;
}

/* SHA-512: supports up to 239 bytes input (two 128-byte blocks). */
void sha512(const uchar* data, int dlen, uchar out[64]) {
    ulong st[8]={
        0x6a09e667f3bcc908UL,0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL,0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL,0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL,0x5be0cd19137e2179UL
    };
    uchar buf[256]; int i;
    for(i=0;i<256;i++) buf[i]=0;
    for(i=0;i<dlen&&i<239;i++) buf[i]=data[i];
    buf[dlen]=0x80;
    ulong bits=(ulong)dlen*8;
    int last_block_end=(dlen<112)?128:256;
    for(i=0;i<8;i++) buf[last_block_end-1-i]=(uchar)(bits>>(i*8));
    ulong blk[16];
    for(i=0;i<16;i++)
        blk[i]=((ulong)buf[i*8+0]<<56)|((ulong)buf[i*8+1]<<48)|
               ((ulong)buf[i*8+2]<<40)|((ulong)buf[i*8+3]<<32)|
               ((ulong)buf[i*8+4]<<24)|((ulong)buf[i*8+5]<<16)|
               ((ulong)buf[i*8+6]<< 8)| (ulong)buf[i*8+7];
    sha512_compress(st,blk);
    if(dlen>=112){
        for(i=0;i<16;i++)
            blk[i]=((ulong)buf[128+i*8+0]<<56)|((ulong)buf[128+i*8+1]<<48)|
                   ((ulong)buf[128+i*8+2]<<40)|((ulong)buf[128+i*8+3]<<32)|
                   ((ulong)buf[128+i*8+4]<<24)|((ulong)buf[128+i*8+5]<<16)|
                   ((ulong)buf[128+i*8+6]<< 8)| (ulong)buf[128+i*8+7];
        sha512_compress(st,blk);
    }
    for(i=0;i<8;i++){
        out[i*8+0]=(uchar)(st[i]>>56); out[i*8+1]=(uchar)(st[i]>>48);
        out[i*8+2]=(uchar)(st[i]>>40); out[i*8+3]=(uchar)(st[i]>>32);
        out[i*8+4]=(uchar)(st[i]>>24); out[i*8+5]=(uchar)(st[i]>>16);
        out[i*8+6]=(uchar)(st[i]>> 8); out[i*8+7]=(uchar)(st[i]);
    }
}

/* ─── AES-256 (column-major state, matching FIPS 197) ─────────────────────── */
__constant uchar SBOX[256]={
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};
__constant uchar INV_SBOX[256]={
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

uchar gmul(uchar a, uchar b){
    uchar p=0; int i;
    for(i=0;i<8;i++){
        if(b&1) p^=a;
        uchar hi=a>>7; a<<=1; if(hi) a^=0x1b; b>>=1;
    }
    return p;
}

/*
 * AES-256 key expand — column-major round keys.
 * rk[round] is a flat 16-byte array where index = col*4+row.
 * This matches the Python pure-Python fallback and FIPS 197.
 */
void aes256_expand(const uchar key[32], uchar rk[15][16]){
    uchar rcon[10]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    uchar w[60][4]; int i,j;
    for(i=0;i<8;i++) for(j=0;j<4;j++) w[i][j]=key[i*4+j];
    for(i=8;i<60;i++){
        uchar t[4]; for(j=0;j<4;j++) t[j]=w[i-1][j];
        if(i%8==0){
            /* RotWord */
            uchar tmp=t[0]; t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=tmp;
            /* SubWord */
            for(j=0;j<4;j++) t[j]=SBOX[t[j]];
            /* XOR Rcon */
            t[0]^=rcon[i/8-1];
        } else if(i%8==4){
            for(j=0;j<4;j++) t[j]=SBOX[t[j]];
        }
        for(j=0;j<4;j++) w[i][j]=w[i-8][j]^t[j];
    }
    /* Build round keys in column-major order: rk[r][col*4+row] */
    for(i=0;i<15;i++)
        for(j=0;j<4;j++){   /* j = col */
            rk[i][j*4+0]=w[i*4+j][0];
            rk[i][j*4+1]=w[i*4+j][1];
            rk[i][j*4+2]=w[i*4+j][2];
            rk[i][j*4+3]=w[i*4+j][3];
        }
}

void aes256_dec_block(uchar blk[16], uchar rk[15][16]){
    int i,c;
    /* AddRoundKey round 14 */
    for(i=0;i<16;i++) blk[i]^=rk[14][i];

    for(int r=13;r>=1;r--){
        /* InvShiftRows */
        uchar tmp;
        tmp=blk[13];blk[13]=blk[9];blk[9]=blk[5];blk[5]=blk[1];blk[1]=tmp;
        tmp=blk[10];blk[10]=blk[2];blk[2]=tmp;
        tmp=blk[14];blk[14]=blk[6];blk[6]=tmp;
        tmp=blk[3];blk[3]=blk[7];blk[7]=blk[11];blk[11]=blk[15];blk[15]=tmp;
        /* InvSubBytes */
        for(i=0;i<16;i++) blk[i]=INV_SBOX[blk[i]];
        /* AddRoundKey */
        for(i=0;i<16;i++) blk[i]^=rk[r][i];
        /* InvMixColumns */
        uchar ns[16];
        for(c=0;c<4;c++){
            uchar s0=blk[c*4],s1=blk[c*4+1],s2=blk[c*4+2],s3=blk[c*4+3];
            ns[c*4]  =gmul(s0,0xe)^gmul(s1,0xb)^gmul(s2,0xd)^gmul(s3,0x9);
            ns[c*4+1]=gmul(s0,0x9)^gmul(s1,0xe)^gmul(s2,0xb)^gmul(s3,0xd);
            ns[c*4+2]=gmul(s0,0xd)^gmul(s1,0x9)^gmul(s2,0xe)^gmul(s3,0xb);
            ns[c*4+3]=gmul(s0,0xb)^gmul(s1,0xd)^gmul(s2,0x9)^gmul(s3,0xe);
        }
        for(i=0;i<16;i++) blk[i]=ns[i];
    }
    /* Final InvShiftRows */
    uchar tmp2;
    tmp2=blk[13];blk[13]=blk[9];blk[9]=blk[5];blk[5]=blk[1];blk[1]=tmp2;
    tmp2=blk[10];blk[10]=blk[2];blk[2]=tmp2;
    tmp2=blk[14];blk[14]=blk[6];blk[6]=tmp2;
    tmp2=blk[3];blk[3]=blk[7];blk[7]=blk[11];blk[11]=blk[15];blk[15]=tmp2;
    /* Final InvSubBytes */
    for(i=0;i<16;i++) blk[i]=INV_SBOX[blk[i]];
    /* AddRoundKey round 0 */
    for(i=0;i<16;i++) blk[i]^=rk[0][i];
}

void aes256_cbc32(const uchar key[32], const uchar iv[16],
                  const __global uchar ct[32], uchar pt[32]){
    uchar rk[15][16]; int i;
    aes256_expand(key,rk);
    uchar blk[16];
    /* Block 0 */
    for(i=0;i<16;i++) blk[i]=ct[i];
    aes256_dec_block(blk,rk);
    for(i=0;i<16;i++) pt[i]=blk[i]^iv[i];
    /* Block 1 */
    for(i=0;i<16;i++) blk[i]=ct[16+i];
    aes256_dec_block(blk,rk);
    for(i=0;i<16;i++) pt[16+i]=blk[i]^ct[i];
}

/* ─── MAIN KERNEL ──────────────────────────────────────────────────────────── */
__kernel void btc_check(
    __global const uchar* passwords,
    __global const uchar* salt,
              const int   salt_len,
    __global const uchar* ct,
              const int   iters,
    __global int*         results,
    __global uchar*       found_pw,
    __global int*         found_flag,
              const int   pw_stride
){
    int gid=get_global_id(0);
    if(*found_flag){ results[gid]=0; return; }

    uchar pw[64]; int pw_len=0,i;
    for(i=0;i<pw_stride&&i<63;i++){
        uchar c=passwords[gid*pw_stride+i];
        if(!c) break;
        pw[pw_len++]=c;
    }

    uchar combined[128]; int clen=pw_len+salt_len;
    for(i=0;i<pw_len;i++)   combined[i]=pw[i];
    for(i=0;i<salt_len;i++) combined[pw_len+i]=salt[i];

    uchar h[64],tmp[64];
    sha512(combined,clen,h);
    for(int r=1;r<iters;r++){
        sha512(h,64,tmp);
        for(i=0;i<64;i++) h[i]=tmp[i];
    }

    uchar key[32],iv[16];
    for(i=0;i<32;i++) key[i]=h[i];
    for(i=0;i<16;i++) iv[i]=h[32+i];

    uchar pt[32];
    aes256_cbc32(key,iv,ct,pt);

    int ok=1;
    for(i=16;i<32;i++) if(pt[i]!=0x10){ ok=0; break; }

    results[gid]=ok;
    if(ok){
        int prev=atomic_cmpxchg(found_flag,0,1);
        if(prev==0)
            for(i=0;i<pw_stride;i++) found_pw[i]=passwords[gid*pw_stride+i];
    }
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# GPU MODE  —  OpenCL engine
# ─────────────────────────────────────────────────────────────────────────────
class GPUEngine:
    PW_STRIDE = 64

    def __init__(self):
        platforms = cl.get_platforms()
        devs      = [d for p in platforms for d in p.get_devices()]
        if not devs:
            raise RuntimeError("No OpenCL device found.")
        gpu_devs    = [d for d in devs if d.type & cl.device_type.GPU]
        self.device = gpu_devs[0] if gpu_devs else devs[0]
        self.ctx    = cl.Context([self.device])
        self.queue  = cl.CommandQueue(self.ctx)
        self.prog   = cl.Program(self.ctx, _OPENCL_SRC).build()

    @property
    def name(self):
        return self.device.name.strip()

    def check_batch(self, parsed: dict, passwords: list):
        mf = cl.mem_flags
        n  = len(passwords)

        pw_buf = np.zeros(n * self.PW_STRIDE, dtype=np.uint8)
        for i, pw in enumerate(passwords):
            b = pw.encode("utf-8")[:self.PW_STRIDE - 1]
            pw_buf[i*self.PW_STRIDE : i*self.PW_STRIDE + len(b)] = list(b)

        salt       = np.frombuffer(parsed["salt_bytes"],        dtype=np.uint8)
        ct         = np.frombuffer(parsed["master_bytes"][:32], dtype=np.uint8)
        results    = np.zeros(n,              dtype=np.int32)
        found_pw   = np.zeros(self.PW_STRIDE, dtype=np.uint8)
        found_flag = np.zeros(1,              dtype=np.int32)

        d_pw   = cl.Buffer(self.ctx, mf.READ_ONLY  | mf.COPY_HOST_PTR, hostbuf=pw_buf)
        d_salt = cl.Buffer(self.ctx, mf.READ_ONLY  | mf.COPY_HOST_PTR, hostbuf=salt)
        d_ct   = cl.Buffer(self.ctx, mf.READ_ONLY  | mf.COPY_HOST_PTR, hostbuf=ct)
        d_res  = cl.Buffer(self.ctx, mf.WRITE_ONLY | mf.COPY_HOST_PTR, hostbuf=results)
        d_fpw  = cl.Buffer(self.ctx, mf.WRITE_ONLY | mf.COPY_HOST_PTR, hostbuf=found_pw)
        d_flag = cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=found_flag)

        self.prog.btc_check(
            self.queue, (n,), None,
            d_pw, d_salt, np.int32(len(salt)),
            d_ct, np.int32(parsed["iterations"]),
            d_res, d_fpw, d_flag,
            np.int32(self.PW_STRIDE),
        )
        self.queue.finish()

        cl.enqueue_copy(self.queue, found_flag, d_flag)
        self.queue.finish()
        if found_flag[0]:
            cl.enqueue_copy(self.queue, found_pw, d_fpw)
            self.queue.finish()
            return bytes(found_pw).split(b'\x00')[0].decode("utf-8", errors="replace")
        return None


def run_gpu(hashes: list, words: list, batch_size: int) -> list:
    gpu = GPUEngine()
    print(f"  GPU  : {cyan(gpu.name)}")
    print(f"  Batch: {batch_size} passwords/dispatch\n")

    results = [{"hash": h["raw"], "status": "not_found",
                "iterations": h["iterations"], "time_s": 0.0}
               for h in hashes]
    total = len(hashes) * len(words)
    prog  = Progress(total)

    for h_idx, parsed in enumerate(hashes):
        t0 = time.time()
        found_pw = None
        for i in range(0, len(words), batch_size):
            batch  = words[i:i+batch_size]
            result = gpu.check_batch(parsed, batch)
            prog.checked += len(batch)
            prog.display()
            if result is not None:
                found_pw = result
                prog.found += 1
                break
        elapsed = time.time() - t0
        results[h_idx]["time_s"] = elapsed
        if found_pw:
            results[h_idx]["status"]   = "found"
            results[h_idx]["password"] = found_pw
            prog.display(force=True)
            print(f"\n  {green('✓ FOUND')}  "
                  f"Hash #{h_idx+1}  →  {bold(green(repr(found_pw)))}")

    prog.display(force=True)
    print()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# FILE I/O
# ─────────────────────────────────────────────────────────────────────────────
def load_targets(path: str) -> list:
    if not os.path.isfile(path):
        sys.exit(red(f"[ERROR] File not found: {path}"))
    hashes, errs = [], 0
    with open(path, encoding="utf-8", errors="ignore") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                hashes.append(parse_hash(line))
            except ParseError as e:
                print(yellow(f"  [SKIP] line {n}: {e}"))
                errs += 1
    if not hashes:
        sys.exit(red("[ERROR] No valid hashes in targets.txt"))
    print(f"  Hashes  : {bold(str(len(hashes)))} valid "
          f"({errs} skipped)  ← {cyan(path)}")
    return hashes


def load_wordlist(path: str) -> list:
    if not os.path.isfile(path):
        sys.exit(red(f"[ERROR] File not found: {path}"))
    words = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if w:
                words.append(w)
    if not words:
        sys.exit(red("[ERROR] Wordlist is empty"))
    print(f"  Wordlist: {bold(str(len(words)))} passwords  ← {cyan(path)}")
    return words


def save_results(results: list, path: str, csv_also: bool):
    found = [r for r in results if r.get("status") == "found"]
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Bitcoin Batch Checker — Results\n")
        f.write(f"# Time     : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"# Found    : {len(found)} / {len(results)}\n\n")
        for r in results:
            tag = "FOUND" if r["status"] == "found" else r["status"].upper()
            f.write(f"[{tag}] {r['hash']}\n")
            if r.get("password"):
                f.write(f"         Password  : {r['password']}\n")
                f.write(f"         Iterations: {r['iterations']}\n")
                f.write(f"         Time      : {r['time_s']:.2f}s\n")
            f.write("\n")
    print(f"  Saved → {cyan(path)}")
    if csv_also:
        cp = path.replace(".txt", ".csv")
        with open(cp, "w", encoding="utf-8") as f:
            f.write("status,password,iterations,time_s,hash\n")
            for r in results:
                f.write(f"{r['status']},{r.get('password','')},"
                        f"{r['iterations']},{r['time_s']:.3f},"
                        f"\"{r['hash']}\"\n")
        print(f"  CSV   → {cyan(cp)}")


# ─────────────────────────────────────────────────────────────────────────────
# SELF-TEST  (runs on startup to catch AES regression)
# ─────────────────────────────────────────────────────────────────────────────
def _self_test():
    """
    Verify pure-Python AES against NIST SP 800-38A AES-256-CBC vector.
    Key:    603deb10...30914dff4
    IV:     00010203...0c0d0e0f
    CT[0]:  f58c4c04d6e5f1ba779eabfb5f7bfbd6
    PT[0]:  6bc1bee22e409f96e93d7e117393172a
    """
    nist_key = bytes.fromhex(
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4")
    nist_iv  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    nist_ct  = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")
    nist_pt  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    # Temporarily disable pycryptodome to test pure-Python path
    global HAS_PYCRYPTO
    orig = HAS_PYCRYPTO
    HAS_PYCRYPTO = False
    result = aes256_cbc_decrypt_nopad(nist_key, nist_iv, nist_ct)
    HAS_PYCRYPTO = orig

    if result != nist_pt:
        print(red("\n[FATAL] Pure-Python AES failed NIST test vector!"))
        print(red(f"  expected: {nist_pt.hex()}"))
        print(red(f"  got     : {result.hex()}"))
        sys.exit(1)

    # Also test known-good hash/password pair
    parsed = parse_hash(
        "$bitcoin$64"
        "$2d06d1d9ceb5ae458c8aab81ec24663c068c5fd65ea7d4ce64601cc24ac53937"
        "$16$aabbccdd11223344$10$2$00$2$00"
    )
    HAS_PYCRYPTO = False
    ok_correct = check_one(parsed, "satoshi")
    ok_wrong   = check_one(parsed, "wrongpassword")
    HAS_PYCRYPTO = orig

    if not ok_correct or ok_wrong:
        print(red("\n[FATAL] AES self-test failed on Bitcoin hash!"))
        print(red(f"  correct password 'satoshi': {ok_correct}  (expected True)"))
        print(red(f"  wrong   password          : {ok_wrong}   (expected False)"))
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Bitcoin wallet.dat batch password checker (CPU + GPU)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bitcoin_checker.py
  python3 bitcoin_checker.py --mode gpu
  python3 bitcoin_checker.py --mode cpu --workers 8
  python3 bitcoin_checker.py --targets targets.txt --wordlist wordlist.txt
  python3 bitcoin_checker.py --output found.txt --csv
        """
    )
    ap.add_argument("--targets",   default="targets.txt")
    ap.add_argument("--wordlist",  default="wordlist.txt")
    ap.add_argument("--output",    default="results.txt")
    ap.add_argument("--mode",      default="auto", choices=["auto","cpu","gpu"])
    ap.add_argument("--workers",   type=int, default=multiprocessing.cpu_count())
    ap.add_argument("--gpu-batch", type=int, default=512)
    ap.add_argument("--csv",       action="store_true")
    ap.add_argument("--no-color",  action="store_true")
    ap.add_argument("--no-selftest", action="store_true",
                    help="Skip AES self-test on startup")
    args = ap.parse_args()

    if args.no_color:
        global _COLOR; _COLOR = False

    print(f"""
{bold(orange('  ₿  Bitcoin / Litecoin wallet.dat  —  Batch Password Checker'))}
  {dim('SHA-512 Iterative · AES-256-CBC · Strict PKCS7 (0x10 × 16)')}
""")

    print(bold("  Dependencies:"))
    print(f"    AES       : {cyan('pycryptodome') if HAS_PYCRYPTO else yellow('pure Python (slow) → pip install pycryptodome')}")
    print(f"    GPU/OpenCL: {cyan('available') if HAS_OPENCL else yellow('not found → pip install pyopencl numpy')}")
    print(f"    CPU cores : {cyan(str(multiprocessing.cpu_count()))}\n")

    # Run self-test before processing any real data
    if not args.no_selftest:
        _self_test()
        print(f"  {green('✓')} AES self-test passed (NIST SP 800-38A + Bitcoin hash)\n")

    print(bold("  Input:"))
    hashes = load_targets(args.targets)
    words  = load_wordlist(args.wordlist)
    print()

    mode = args.mode
    if mode == "auto":
        mode = "gpu" if HAS_OPENCL else "cpu"
    if mode == "gpu" and not HAS_OPENCL:
        print(yellow("  [!] GPU requested but pyopencl not found → falling back to CPU\n"))
        mode = "cpu"

    total = len(hashes) * len(words)
    print(bold(f"  Mode     : {cyan(mode.upper())}" +
               (f"  (workers={args.workers})" if mode=="cpu" else "")))
    print(bold(f"  Total ops: {cyan(f'{total:,}')}  ({len(hashes)} hashes × {len(words)} passwords)"))
    print(bold(f"  Output   : {cyan(args.output)}"))
    print(f"\n  {dim('─'*50)}\n")

    t0 = time.time()
    try:
        if mode == "gpu":
            results = run_gpu(hashes, words, args.gpu_batch)
        else:
            results = run_cpu(hashes, words, args.workers)
    except KeyboardInterrupt:
        print(f"\n\n  {yellow('[!] Interrupted.')}")
        sys.exit(0)

    elapsed = time.time() - t0
    found   = [r for r in results if r.get("status") == "found"]

    print(f"\n  {dim('─'*50)}")
    print(bold("  SUMMARY"))
    print(f"  {'Total hashes':<22}: {len(hashes)}")
    print(f"  {'Total passwords':<22}: {len(words)}")
    print(f"  {'Found':<22}: {green(str(len(found)))}")
    print(f"  {'Not found':<22}: {red(str(len(results)-len(found)))}")
    print(f"  {'Time':<22}: {elapsed:.1f}s")
    if elapsed > 0:
        print(f"  {'Speed':<22}: {total/elapsed:.1f} ops/s\n")

    if found:
        print(bold(green("  ✓ PASSWORDS FOUND:")))
        for r in found:
            print(f"    {green('→')} {bold(green(repr(r['password'])))}  "
                  f"{dim(r['hash'][:55]+'...')}")
        print()

    save_results(results, args.output, args.csv)
    print(bold("\n  Done ✓"))


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
