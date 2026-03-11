"""
crypto.py - Core encryption / decryption functions for AnonShare.

Encryption stack:
  Layer 1 (always):   ChaCha20-Poly1305  (via `cryptography` library)
                       – functionally equivalent to NaCl SecretBox / XSalsa20-Poly1305
                       – falls back to PyNaCl SecretBox when available
  Layer 2 (optional): AES-256-GCM        (independent key, --double-encrypt)

Key derivation:
  PBKDF2-HMAC-SHA256 (100 000 iterations) → HKDF-SHA256 expansion

Install PyNaCl for the authentic NaCl SecretBox primitive:
  pip install PyNaCl
Without it the pure-cryptography ChaCha20-Poly1305 layer is used instead
(same security properties, different wire format).
"""

from __future__ import annotations

import os
import struct
import hashlib

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from config import (
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    PADDING_BLOCK_SIZE,
    ENABLE_PADDING,
)

# Try to use PyNaCl for the primary layer when available.
try:
    import nacl.secret
    import nacl.utils
    _NACL_AVAILABLE = True
except ImportError:
    _NACL_AVAILABLE = False


# ------------------------------------------------------------------ helpers --

def _pad(data: bytes) -> bytes:
    """Pad *data* to the next PADDING_BLOCK_SIZE boundary.

    Layout: [4-byte LE original-length][data][random padding]
    """
    original_len = len(data)
    header = struct.pack("<I", original_len)
    total_payload = len(header) + original_len
    remainder = total_payload % PADDING_BLOCK_SIZE
    pad_len = (PADDING_BLOCK_SIZE - remainder) % PADDING_BLOCK_SIZE
    return header + data + os.urandom(pad_len)


def _unpad(padded: bytes) -> bytes:
    """Reverse _pad – extract original bytes using stored length."""
    (original_len,) = struct.unpack("<I", padded[:4])
    return padded[4 : 4 + original_len]


# --------------------------------------------------------------- public API --

def derive_key_from_passphrase(
    passphrase: str,
    salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Derive a 256-bit encryption key from *passphrase* via PBKDF2 + HKDF.

    Returns ``(key_bytes, salt_bytes)``.
    """
    if salt is None:
        salt = os.urandom(16)

    pbkdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw_key = pbkdf2.derive(passphrase.encode("utf-8"))

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,
        info=b"anonshare-passphrase-key-v1",
    )
    key = hkdf.derive(raw_key)
    return key, salt


def sha256_file(file_path: str) -> str:
    """Return the hex SHA-256 digest of *file_path* using streaming reads."""
    h = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------- primary layer ---

def _primary_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt using NaCl SecretBox if available, else ChaCha20-Poly1305."""
    if ENABLE_PADDING:
        plaintext = _pad(plaintext)
    if _NACL_AVAILABLE:
        box = nacl.secret.SecretBox(key)
        return bytes(box.encrypt(plaintext))
    # ChaCha20-Poly1305 fallback: prepend 12-byte nonce
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ct = chacha.encrypt(nonce, plaintext, None)
    return nonce + ct


def _primary_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt the primary layer."""
    if _NACL_AVAILABLE:
        box = nacl.secret.SecretBox(key)
        plaintext = bytes(box.decrypt(ciphertext))
    else:
        nonce, ct = ciphertext[:12], ciphertext[12:]
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ct, None)
    if ENABLE_PADDING:
        plaintext = _unpad(plaintext)
    return plaintext


# Expose as nacl_encrypt / nacl_decrypt for backward compat with tests
nacl_encrypt = _primary_encrypt
nacl_decrypt = _primary_decrypt


# ---------------------------------------------------------- AES-256-GCM -----

def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt *plaintext* with AES-256-GCM.

    Output layout: [12-byte nonce][ciphertext+tag]
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def aes_gcm_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM blob produced by :func:`aes_gcm_encrypt`."""
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# -------------------------------------------------------- high-level encrypt -

def encrypt_payload(
    plaintext: bytes,
    primary_key: bytes,
    extra_key: bytes | None = None,
) -> bytes:
    """Full encryption pipeline used by the sender.

    If *extra_key* is provided, AES-256-GCM is applied first, then the
    primary layer (NaCl/ChaCha20-Poly1305) wraps the result.
    """
    if extra_key is not None:
        plaintext = aes_gcm_encrypt(plaintext, extra_key)
    return _primary_encrypt(plaintext, primary_key)


def decrypt_payload(
    ciphertext: bytes,
    primary_key: bytes,
    extra_key: bytes | None = None,
) -> bytes:
    """Reverse of :func:`encrypt_payload`."""
    plaintext = _primary_decrypt(ciphertext, primary_key)
    if extra_key is not None:
        plaintext = aes_gcm_decrypt(plaintext, extra_key)
    return plaintext
