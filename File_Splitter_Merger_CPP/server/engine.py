"""
SecureVault Engine
==================

Pure-Python file fragmentation / reconstruction engine.

Features over the original C++ engine:
  * Cross-platform (no binary needed).
  * k-of-n threshold reconstruction, for real: the payload is erasure-coded
    with a systematic Cauchy Reed-Solomon matrix, so ANY k of the n fragments
    rebuild the file (the remaining n-k fragments act as parity).
  * The 256-bit content key is additionally Shamir-shared across fragments,
    so fewer than k fragments reveal neither data nor key.
  * Self-describing fragments (".svf"): a JSON header rides inside every
    fragment - no manifest file needed to reconstruct.
  * scrypt password KDF, random IV per fragment, AES-256-CBC.
  * SHA-256 integrity hashes per fragment and for the whole file.
  * Backward compatible: can merge raw ".enc" fragments produced by the
    original C++/OpenSSL engine (EVP_BytesToKey, 1 iteration, no salt).

Fragment binary layout:
    magic      7 bytes   b"SVFRG1\\0"
    hdr_len    4 bytes   uint32 little-endian
    header     JSON (utf-8)
    payload    ciphertext (or plaintext when mode == "none")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from typing import Iterable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

MAGIC = b"SVFRG1\0"

MODE_NONE = "none"
MODE_PASSWORD = "password"
MODE_SHAMIR = "shamir"


class EngineError(Exception):
    """User-facing engine failure (bad password, not enough fragments...)."""


# --------------------------------------------------------------------------
# GF(2^8) arithmetic - AES irreducible polynomial 0x11B
# --------------------------------------------------------------------------

def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gpow(a: int, e: int) -> int:
    r = 1
    while e:
        if e & 1:
            r = _gmul(r, a)
        a = _gmul(a, a)
        e >>= 1
    return r


def _ginv(a: int) -> int:
    if a == 0:
        raise EngineError("Cannot invert 0 in GF(2^8)")
    return _gpow(a, 254)


def _mul_table(coef: int) -> bytes:
    """256-byte translation table for fast bytewise multiplication."""
    return bytes(_gmul(coef, i) for i in range(256))


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


# --------------------------------------------------------------------------
# Shamir's Secret Sharing over GF(2^8) - guards the 256-bit content key
# --------------------------------------------------------------------------

def split_secret(key: bytes, k: int, n: int) -> list[tuple[int, bytes]]:
    """Split a 32-byte key into n shares, any k of which recover it."""
    if not 1 <= k <= n:
        raise EngineError("Threshold must satisfy 1 <= k <= n")
    if len(key) != 32:
        raise EngineError("Secret must be 32 bytes")

    # Independent random polynomial per byte position; c0 is the secret byte.
    coeffs = [[key[j]] + [secrets.token_bytes(1)[0] for _ in range(k - 1)]
              for j in range(32)]

    shares: list[tuple[int, bytes]] = []
    for i in range(1, n + 1):
        x = i
        y = bytearray(32)
        for j in range(32):
            acc = 0
            for c in reversed(coeffs[j]):          # Horner evaluation
                acc = _gmul(acc, x) ^ c
            y[j] = acc
        shares.append((x, bytes(y)))
    return shares


def combine_secret(shares: list[tuple[int, bytes]]) -> bytes:
    """Lagrange interpolation at x = 0 over exactly k shares."""
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise EngineError("Duplicate share indices")
    key = bytearray(32)
    for j in range(32):
        acc = 0
        for xi, yi in shares:
            num, den = 1, 1
            for xj, _ in shares:
                if xj == xi:
                    continue
                num = _gmul(num, xj)        # (0 - xj) == xj in GF(2^8)
                den = _gmul(den, xi ^ xj)   # (xi - xj) == xi ^ xj
            acc ^= _gmul(yi[j], _gmul(num, _ginv(den)))
        key[j] = acc
    return bytes(key)


# --------------------------------------------------------------------------
# Reed-Solomon erasure coding (systematic Cauchy matrix, MDS)
# --------------------------------------------------------------------------

def _rs_matrix(n: int, k: int) -> list[list[int]]:
    """n x k matrix: k identity rows (data) + n-k Cauchy parity rows.
    Cauchy guarantees every k x k submatrix is invertible -> any k of n
    fragments reconstruct the payload."""
    rows = [[1 if c == r else 0 for c in range(k)] for r in range(k)]
    for r in range(n - k):
        xr = k + r
        rows.append([_ginv(xr ^ c) for c in range(k)])   # 1/(x_r ^ y_c)
    return rows


def _rs_encode(data: bytes, n: int, k: int) -> list[bytes]:
    """Encode *data* into n shards; the first k are the raw data shards."""
    pad = (k - len(data) % k) % k
    data += b"\x00" * pad
    shard_len = len(data) // k
    shards = [data[i * shard_len:(i + 1) * shard_len] for i in range(k)]

    rows = _rs_matrix(n, k)
    for r in range(k, n):
        enc = bytes(shard_len)
        for c in range(k):
            coef = rows[r][c]
            if coef == 0:
                continue
            if coef == 1:
                enc = _xor(enc, shards[c])
            else:
                enc = _xor(enc, shards[c].translate(_mul_table(coef)))
        shards.append(enc)
    return shards


def _mat_inv_gf256(matrix: list[list[int]], k: int) -> list[list[int]]:
    aug = [row[:] + [1 if i == r else 0 for i in range(k)]
           for r, row in enumerate(matrix)]
    for col in range(k):
        piv = next((r for r in range(col, k) if aug[r][col]), None)
        if piv is None:
            raise EngineError("Erasure code matrix became singular")
        aug[col], aug[piv] = aug[piv], aug[col]
        pinv = _ginv(aug[col][col])
        aug[col] = [_gmul(pinv, v) for v in aug[col]]
        for r in range(k):
            if r != col and aug[r][col]:
                f = aug[r][col]
                aug[r] = [v ^ _gmul(f, w) for v, w in zip(aug[r], aug[col])]
    return [row[k:] for row in aug]


def _rs_decode(present: dict[int, bytes], n: int, k: int) -> bytes:
    """Rebuild the payload from any k shards given as {row_index: shard}."""
    if len(present) < k:
        raise EngineError(f"Need {k} shards, have {len(present)}")
    shard_len = len(next(iter(present.values())))

    rows = _rs_matrix(n, k)
    used = sorted(present)[:k]
    inv = _mat_inv_gf256([rows[r] for r in used], k)

    data = b""
    for c in range(k):
        col = bytes(shard_len)
        for i in range(k):
            coef = inv[c][i]
            if coef == 0:
                continue
            shard = present[used[i]]
            if coef == 1:
                col = _xor(col, shard)
            else:
                col = _xor(col, shard.translate(_mul_table(coef)))
        data += col
    return data


# --------------------------------------------------------------------------
# Crypto primitives
# --------------------------------------------------------------------------

def _derive_key_scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt,
                          n=2 ** 14, r=8, p=1, dklen=32)


def _evp_bytes_to_key(password: str) -> tuple[bytes, bytes]:
    """Replicates OpenSSL EVP_BytesToKey(SHA256, 1 iteration, no salt) used
    by the original C++ engine, for legacy fragment compatibility."""
    d = b""
    prev = b""
    while len(d) < 48:
        prev = hashlib.sha256(prev + password.encode("utf-8")).digest()
        d += prev
    return d[:32], d[32:48]


def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    padder = PKCS7(128).padder()
    data = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise EngineError("Wrong password or corrupted fragment") from exc


# --------------------------------------------------------------------------
# Fragment container
# --------------------------------------------------------------------------

def _read_fragment(path: str) -> tuple[dict, bytes]:
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < len(MAGIC) + 4 or not blob.startswith(MAGIC):
        raise EngineError(f"'{os.path.basename(path)}' is not a SecureVault fragment")
    hdr_len = int.from_bytes(blob[len(MAGIC):len(MAGIC) + 4], "little")
    start = len(MAGIC) + 4
    try:
        header = json.loads(blob[start:start + hdr_len].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EngineError(f"'{os.path.basename(path)}' has a damaged header") from exc
    payload = blob[start + hdr_len:]
    digest = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(digest, header.get("sha256", "")):
        raise EngineError(f"Integrity check failed for '{os.path.basename(path)}'")
    return header, payload


def inspect_fragment(path: str) -> dict:
    """Parse a fragment and return its header + integrity status."""
    header, payload = _read_fragment(path)
    out = dict(header)
    out["filename"] = os.path.basename(path)
    out["payload_bytes"] = len(payload)
    out["integrity"] = "ok"
    return out


# --------------------------------------------------------------------------
# Split
# --------------------------------------------------------------------------

def split_file(src: str, out_dir: str, parts: int, threshold: int,
               mode: str, password: str) -> dict:
    """Fragment *src* into *parts* self-describing shards inside *out_dir*.

    threshold (k)  - minimum fragments needed to reconstruct; the file is
                     erasure-coded so ANY k of the *parts* (n) shards work.
    mode:
      "none"     shards stored in the clear (integrity hashes still apply)
      "password" shards encrypted with an scrypt-derived key
      "shamir"   random content key, Shamir-shared across the shards
    """
    if parts < 2:
        raise EngineError("Number of parts must be at least 2")
    if not 1 <= threshold <= parts:
        raise EngineError("Threshold must be between 1 and the number of parts")
    if mode == MODE_PASSWORD and not password:
        raise EngineError("Password mode requires a password")

    os.makedirs(out_dir, exist_ok=True)
    original = os.path.basename(src)
    with open(src, "rb") as fh:
        data = fh.read()
    size = len(data)

    content_key = b""
    salt = b""
    shares: list[tuple[int, bytes]] = []

    if mode == MODE_PASSWORD:
        salt = secrets.token_bytes(16)
        content_key = _derive_key_scrypt(password, salt)
    elif mode == MODE_SHAMIR:
        content_key = secrets.token_bytes(32)
        shares = split_secret(content_key, threshold, parts)

    shards = _rs_encode(data, parts, threshold)
    total_sha = hashlib.sha256(data).hexdigest()
    fragment_names = []
    fragment_meta = []

    for i, shard in enumerate(shards, start=1):
        iv = b""
        header = {
            "v": 1,
            "original": original,
            "size": size,
            "part": i,
            "parts": parts,
            "threshold": threshold,
            "mode": mode,
            "total_sha256": total_sha,
            "plain_sha256": hashlib.sha256(shard).hexdigest(),
        }

        if mode == MODE_NONE:
            cipher = shard
        else:
            iv = secrets.token_bytes(16)
            cipher = _aes_cbc_encrypt(content_key, iv, shard)
            header["iv"] = iv.hex()
            if mode == MODE_PASSWORD:
                header["kdf"] = {"name": "scrypt", "n": 2 ** 14, "r": 8, "p": 1,
                                 "salt": salt.hex()}
            else:
                x, y = shares[i - 1]
                header["share"] = {"x": x, "y": y.hex()}

        header["sha256"] = hashlib.sha256(cipher).hexdigest()
        hdr = json.dumps(header, separators=(",", ":")).encode("utf-8")

        name = f"{original}.sv{i}of{parts}"
        with open(os.path.join(out_dir, name), "wb") as fout:
            fout.write(MAGIC)
            fout.write(len(hdr).to_bytes(4, "little"))
            fout.write(hdr)
            fout.write(cipher)
        fragment_names.append(name)
        fragment_meta.append({
            "name": name, "part": i,
            "bytes": os.path.getsize(os.path.join(out_dir, name)),
            "sha256": header["sha256"],
            "share_x": header.get("share", {}).get("x"),
        })

    manifest = {
        "id": uuid.uuid4().hex[:12],
        "original": original,
        "size": size,
        "parts": parts,
        "threshold": threshold,
        "mode": mode,
        "total_sha256": total_sha,
        "fragments": fragment_meta,
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


# --------------------------------------------------------------------------
# Merge
# --------------------------------------------------------------------------

def merge_fragments(fragment_paths: Iterable[str], out_path: str,
                    password: str = "") -> dict:
    """Reconstruct the original file from ANY >= threshold set of fragments."""
    frags = []
    for p in fragment_paths:
        header, payload = _read_fragment(p)
        frags.append((header, payload))
    if not frags:
        raise EngineError("No fragments supplied")

    ref = frags[0][0]
    for h, _ in frags[1:]:
        if (h["original"], h["parts"], h["threshold"], h["mode"]) != \
                (ref["original"], ref["parts"], ref["threshold"], ref["mode"]):
            raise EngineError("Fragments do not belong to the same split set")

    seen: dict[int, tuple[dict, bytes]] = {}
    for h, payload in frags:
        if h["part"] in seen:
            raise EngineError(f"Duplicate fragment #{h['part']} supplied")
        seen[h["part"]] = (h, payload)

    k, n, mode = ref["threshold"], ref["parts"], ref["mode"]
    if len(seen) < k:
        raise EngineError(
            f"Threshold not met: {len(seen)}/{k} fragments supplied "
            f"(this set needs any {k} of {n})")

    content_key = b""
    if mode == MODE_PASSWORD:
        if not password:
            raise EngineError("This set is password protected - enter the password")
        kdf = ref.get("kdf", {})
        if kdf.get("name") == "legacy-openssl":
            content_key, _ = _evp_bytes_to_key(password)
        else:
            content_key = _derive_key_scrypt(password, bytes.fromhex(kdf["salt"]))
    elif mode == MODE_SHAMIR:
        distinct: dict[int, bytes] = {}
        for h, _ in seen.values():
            s = h["share"]
            distinct[s["x"]] = bytes.fromhex(s["y"])
        if len(distinct) < k:
            raise EngineError(
                f"Only {len(distinct)} usable key shares found, need {k}")
        picks = sorted(distinct.items())[:k]
        content_key = combine_secret([(x, y) for x, y in picks])

    # Decrypt each present shard (verify its content hash on the way).
    clear_shards: dict[int, bytes] = {}
    for part, (h, payload) in seen.items():
        shard = payload
        if mode != MODE_NONE:
            shard = _aes_cbc_decrypt(content_key, bytes.fromhex(h["iv"]), payload)
        digest = hashlib.sha256(shard).hexdigest()
        if not hmac.compare_digest(digest, h["plain_sha256"]):
            raise EngineError(f"Content mismatch in fragment #{part} - wrong password?")
        clear_shards[part - 1] = shard

    data = _rs_decode(clear_shards, n, k)[:ref["size"]]
    digest = hashlib.sha256(data).hexdigest()
    ok = hmac.compare_digest(digest, ref["total_sha256"])

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "wb") as fout:
        fout.write(data)

    return {
        "original": ref["original"],
        "size": len(data),
        "fragments_used": len(seen),
        "threshold": k,
        "parts": n,
        "total_sha256": digest,
        "integrity": "verified" if ok else "MISMATCH",
        "output": os.path.basename(out_path),
    }


# --------------------------------------------------------------------------
# Legacy compatibility: raw ".enc" fragments from the original C++ engine
# --------------------------------------------------------------------------

def merge_legacy_enc(fragment_paths: Iterable[str], out_path: str,
                     password: str, original: str = "") -> dict:
    """Merge OpenSSL-encrypted '.enc' parts produced by the original
    C++ backend (EVP_BytesToKey / AES-256-CBC, concatenated in order)."""
    paths = list(fragment_paths)
    key, iv = _evp_bytes_to_key(password)
    total_hash = hashlib.sha256()
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "wb") as fout:
        for p in paths:
            with open(p, "rb") as fh:
                cipher = fh.read()
            plain = _aes_cbc_decrypt(key, iv, cipher)
            total_hash.update(plain)
            fout.write(plain)
    return {
        "original": original or os.path.basename(out_path),
        "size": os.path.getsize(out_path),
        "fragments_used": len(paths),
        "format": "legacy-openssl",
        "total_sha256": total_hash.hexdigest(),
        "output": os.path.basename(out_path),
    }
