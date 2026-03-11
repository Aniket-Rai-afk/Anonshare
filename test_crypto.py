"""
tests/test_crypto.py - Unit tests for crypto.py
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from crypto import (
    derive_key_from_passphrase,
    nacl_encrypt,
    nacl_decrypt,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    encrypt_payload,
    decrypt_payload,
    sha256_bytes,
)


class TestKeyDerivation:
    def test_same_passphrase_same_salt_yields_same_key(self):
        key1, salt = derive_key_from_passphrase("CorrectHorseBatteryStaple")
        key2, _    = derive_key_from_passphrase("CorrectHorseBatteryStaple", salt)
        assert key1 == key2

    def test_different_salts_yield_different_keys(self):
        key1, salt1 = derive_key_from_passphrase("password123456")
        key2, salt2 = derive_key_from_passphrase("password123456")
        # Salts are random; keys should differ (astronomically unlikely to collide)
        assert salt1 != salt2
        assert key1 != key2

    def test_different_passphrases_yield_different_keys(self):
        key1, salt = derive_key_from_passphrase("passphrase-one-12")
        key2, _    = derive_key_from_passphrase("passphrase-two-12", salt)
        assert key1 != key2

    def test_key_is_32_bytes(self):
        key, _ = derive_key_from_passphrase("some-passphrase-!")
        assert len(key) == 32


class TestNaClSecretBox:
    def test_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"Top secret payload"
        ct = nacl_encrypt(plaintext, key)
        assert nacl_decrypt(ct, key) == plaintext

    def test_wrong_key_raises(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct = nacl_encrypt(b"hello", key1)
        with pytest.raises(Exception):
            nacl_decrypt(ct, key2)

    def test_ciphertext_differs_from_plaintext(self):
        key = os.urandom(32)
        pt = b"A" * 100
        ct = nacl_encrypt(pt, key)
        assert ct != pt

    def test_large_payload(self):
        key = os.urandom(32)
        pt = os.urandom(5 * 1024 * 1024)   # 5 MB
        ct = nacl_encrypt(pt, key)
        assert nacl_decrypt(ct, key) == pt


class TestAesGcm:
    def test_roundtrip(self):
        key = os.urandom(32)
        pt = b"AES-GCM test data"
        ct = aes_gcm_encrypt(pt, key)
        assert aes_gcm_decrypt(ct, key) == pt

    def test_nonce_is_prepended(self):
        key = os.urandom(32)
        ct = aes_gcm_encrypt(b"data", key)
        assert len(ct) > 12     # at least nonce + ciphertext + tag

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(32)
        ct = bytearray(aes_gcm_encrypt(b"sensitive", key))
        ct[-1] ^= 0xFF          # flip a bit in the tag
        with pytest.raises(Exception):
            aes_gcm_decrypt(bytes(ct), key)


class TestPayloadPipeline:
    def test_single_layer(self):
        key = os.urandom(32)
        pt = b"Single layer test"
        ct = encrypt_payload(pt, primary_key=key)
        assert decrypt_payload(ct, primary_key=key) == pt

    def test_double_layer(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        pt = b"Double layer test payload"
        ct = encrypt_payload(pt, primary_key=key1, extra_key=key2)
        assert decrypt_payload(ct, primary_key=key1, extra_key=key2) == pt

    def test_double_layer_wrong_extra_key_raises(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        key2_bad = os.urandom(32)
        ct = encrypt_payload(b"data", primary_key=key1, extra_key=key2)
        with pytest.raises(Exception):
            decrypt_payload(ct, primary_key=key1, extra_key=key2_bad)


class TestSha256:
    def test_known_hash(self):
        # SHA-256 of b"" is well-known
        assert sha256_bytes(b"") == \
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_deterministic(self):
        data = b"AnonShare integrity test"
        assert sha256_bytes(data) == sha256_bytes(data)
