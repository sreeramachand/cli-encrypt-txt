# cli_encrypt_txt/__main__.py
# AES-256-GCM + Argon2id (password mode only)
# File format (little-endian):
# magic(4)="QF01" | mode(1): 0x01=password-argon2id | header_len(2) |
# header(bytes) | nonce(12) | ciphertext+tag
#
# Password header (mode 0x01): {
#   "kdf":"argon2id","m":mem_kib,"t":time_cost,"p":parallelism,"salt":b64
# }

import argparse, json, os, sys, base64, zlib, hashlib
from getpass import getpass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----- Argon2id (password KDF) -----
try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    _HAS_ARGON2 = True
except Exception:
    _HAS_ARGON2 = False

MAGIC = b"QF01"
MODE_PW = 0x01

def _write_file_safely(path: str, data: bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)

# ---------- Password (Argon2id) ----------
def argon2id_derive_key(password: str, salt: bytes,
                        m_kib: int = 256 * 1024,  # 256 MiB
                        t_cost: int = 3,
                        parallelism: int = 4) -> Tuple[bytes, dict]:
    if not _HAS_ARGON2:
        print("Missing dependency: argon2-cffi. Install it to use password mode.", file=sys.stderr)
        sys.exit(2)
    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=t_cost,
        memory_cost=m_kib,
        parallelism=parallelism,
        hash_len=32,
        type=Argon2Type.ID,
    )
    meta = {"mode": MODE_PW, "kdf":"argon2id","m":m_kib,"t":t_cost,"p":parallelism,"salt":base64.b64encode(salt).decode()}
    return key, meta

def argon2id_derive_from_header(password: str, meta: dict) -> bytes:
    try:
        salt_b64 = meta["salt"]
        t = int(meta["t"]); m = int(meta["m"]); p = int(meta["p"])
    except Exception as e:
        raise ValueError(f"Invalid header fields for Argon2id: {e}")
    salt = base64.b64decode(salt_b64)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=32,
        type=Argon2Type.ID,
    )

# ---------- Opaque header helpers ----------
def _shake_stream(nonce: bytes, label: bytes, nbytes: int) -> bytes:
    sh = hashlib.shake_256()
    sh.update(nonce + label)
    return sh.digest(nbytes)

def _stego_pack(nonce: bytes, header_json: dict) -> bytes:
    raw = json.dumps(header_json, separators=(',',':')).encode('utf-8')
    comp = zlib.compress(raw, level=9)
    ks = _shake_stream(nonce, b"hdr", len(comp))
    return bytes(a ^ b for a, b in zip(comp, ks))

def _stego_unpack(nonce: bytes, blob: bytes) -> dict:
    ks = _shake_stream(nonce, b"hdr", len(blob))
    comp = bytes(a ^ b for a, b in zip(blob, ks))
    raw = zlib.decompress(comp)
    return json.loads(raw)

# ---------- Payload assembly / parsing ----------
def _assemble_payload(nonce: bytes, ciphertext: bytes, header_json: dict) -> bytes:
    stego_blob = _stego_pack(nonce, header_json)
    stego_len = len(stego_blob).to_bytes(2, 'little')
    payload = MAGIC + nonce + ciphertext + stego_blob + stego_len
    return payload

def _assemble_file(cover_bytes: bytes, payload: bytes) -> bytes:
    # EOF trailer: stego_len(2) (duplicated for easy seek) + payload_len(4)
    stego_len = int.from_bytes(payload[-2:], 'little')
    trailer = stego_len.to_bytes(2, 'little') + len(payload).to_bytes(4, 'little')
    return cover_bytes + payload + trailer

def _read_payload_from_file(blob: bytes) -> bytes:
    if len(blob) < 6:
        raise ValueError("File too small for trailer")
    # Read EOF trailer
    stego_len = int.from_bytes(blob[-6:-4], 'little')
    payload_len = int.from_bytes(blob[-4:], 'little')
    if payload_len < (4 + 12 + 2) or payload_len > len(blob) - 6:
        raise ValueError("Invalid payload length in trailer")
    start = len(blob) - 6 - payload_len
    payload = blob[start: start + payload_len]
    if payload[:4] != MAGIC:
        raise ValueError("Bad magic inside payload")
    return payload

def _parse_payload(payload: bytes):
    # payload: MAGIC | nonce(12) | ciphertext | stego_blob | stego_len(2)
    if len(payload) < 4 + 12 + 2:
        raise ValueError("Truncated payload")
    nonce = payload[4:16]
    stego_len = int.from_bytes(payload[-2:], 'little')
    if stego_len < 1 or stego_len > len(payload) - (4 + 12 + 2):
        raise ValueError("Invalid stego length")
    stego_blob = payload[-2 - stego_len : -2]
    ciphertext = payload[16 : -2 - stego_len]
    header = _stego_unpack(nonce, stego_blob)
    return nonce, header, ciphertext

# ---------- Encrypt / Decrypt / Inspect ----------
def _default_enc_outpath(input_path: str, cover_path: str | None) -> str:
    base = os.path.basename(input_path)
    if cover_path:
        ext = os.path.splitext(cover_path)[1] or ".bin"
        return base + ".enc" + ext
    else:
        return input_path + ".enc"

def _default_dec_outpath(enc_path: str) -> str:
    # If file ends with ".enc", strip once; else append ".dec"
    if enc_path.lower().endswith(".enc"):
        return enc_path[:-4]
    # strip ".enc.<ext>" style:
    name, ext = os.path.splitext(enc_path)
    if name.lower().endswith(".enc"):
        return name[:-4] + (ext or "")
    return enc_path + ".dec"

def encrypt(input_path: str, password: str, m_kib=256*1024, t_cost=3, p=4, cover: str | None = None, out: str | None = None):
    pt = open(input_path, "rb").read()
    salt = os.urandom(16)
    key, meta = argon2id_derive_key(password, salt, m_kib, t_cost, p)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, pt, None)

    payload = _assemble_payload(nonce, ct, meta)
    cover_bytes = open(cover, "rb").read() if cover else b""
    final = _assemble_file(cover_bytes, payload)

    out_path = out or _default_enc_outpath(input_path, cover)
    _write_file_safely(out_path, final)
    if cover:
        print(f"[+] Encrypted with opaque header + stego into cover: {out_path}")
    else:
        print(f"[+] Encrypted (opaque header): {out_path}")

def decrypt(input_path: str):
    blob = open(input_path, "rb").read()
    payload = _read_payload_from_file(blob)
    nonce, header, ct = _parse_payload(payload)
    if int(header.get("mode", 0)) != MODE_PW:
        raise ValueError("Unsupported mode in header (expected password mode)")
    # up to 5 attempts, never delete user data
    for attempt in range(1, 6):
        pw = getpass(f"Attempt {attempt}/5 - Enter password: ")
        try:
            key = argon2id_derive_from_header(pw, header)
            pt = AESGCM(key).decrypt(nonce, ct, None)
            out_path = _default_dec_outpath(input_path)
            _write_file_safely(out_path, pt)
            print(f"✅ Decryption successful: {out_path}")
            return
        except Exception:
            print("❌ Invalid password or corrupted file.")
    print("Maximum attempts exceeded. Keeping the encrypted file.")

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="File encryptor (AES-256-GCM + Argon2id, opaque header + stego).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Encrypt
    p_enc = sub.add_parser("encrypt", help="Encrypt a file (password mode)")
    p_enc.add_argument("file")
    p_enc.add_argument("--password", "-p", help="Password (prompted if omitted)")
    p_enc.add_argument("--m-kib", type=int, default=256*1024, help="Argon2id memory (KiB); default 262144 (256 MiB)")
    p_enc.add_argument("--t-cost", type=int, default=3, help="Argon2id iterations; default 3")
    p_enc.add_argument("--parallelism", type=int, default=4, help="Argon2id parallelism; default 4")
    p_enc.add_argument("--cover", help="Optional cover file to embed payload (e.g., cover.jpg)")
    p_enc.add_argument("--out", help="Optional output path")

    # Decrypt
    p_dec = sub.add_parser("decrypt", help="Decrypt a file (password mode)")
    p_dec.add_argument("file")


    args = parser.parse_args()

    if args.cmd == "encrypt":
        password = args.password or getpass("Enter password: ")
        encrypt(args.file, password, args.m_kib, args.t_cost, args.parallelism, args.cover, args.out)
        return

    if args.cmd == "decrypt":
        decrypt(args.file)
        return

if __name__ == "__main__":
    main()
