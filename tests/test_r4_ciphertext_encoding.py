"""Ciphertext encoding must not create the seeded base64 scan collision."""
import base64
from unittest.mock import Mock

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aegis import evidence


@pytest.fixture
def key(monkeypatch):
    key = bytes(range(32))  # Deterministic test key, not a production secret.
    monkeypatch.setattr(evidence, "_key_cache", key)
    return key


def test_ciphertext_base64_collision_is_encoded_as_hex(key, monkeypatch):
    nonce = bytes(range(12))
    ciphertext = base64.urlsafe_b64decode("610k") + bytes(16)
    assert "610k" in base64.urlsafe_b64encode(nonce + ciphertext).decode()
    cipher = Mock()
    cipher.encrypt.return_value = ciphertext
    aes = Mock(return_value=cipher)
    random = Mock(return_value=nonce)
    monkeypatch.setattr(evidence, "AESGCM", aes)
    monkeypatch.setattr(evidence.os, "urandom", random)

    stored = evidence.enc("ordinary evidence")

    assert "610k" not in stored
    key_id = __import__('hashlib').sha256(key).hexdigest()[:32]
    header = 'enc:v2:' + key_id + ':'
    assert stored == header + (nonce + ciphertext).hex()
    random.assert_called_once_with(12)
    aes.assert_called_once_with(key)
    cipher.encrypt.assert_called_once_with(nonce, b"ordinary evidence", header.encode())


def test_legacy_base64_decrypt_and_idempotence(key):
    nonce = bytes(range(12))
    ciphertext = AESGCM(key).encrypt(nonce, b"existing evidence", None)
    stored = "enc:v1:" + base64.urlsafe_b64encode(nonce + ciphertext).decode()
    assert evidence.dec(stored) == "existing evidence"
    assert evidence.enc(stored) == stored


def test_hex_roundtrip_random_nonce_and_idempotence(key):
    first = evidence.enc("new evidence")
    second = evidence.enc("new evidence")
    assert first.startswith("enc:v2:")
    assert second.startswith("enc:v2:")
    first_blob = bytes.fromhex(first[len("enc:v2:"):].split(':', 1)[1])
    second_blob = bytes.fromhex(second[len("enc:v2:"):].split(':', 1)[1])
    assert len(first_blob) == 12 + len(b"new evidence") + 16
    assert first_blob[:12] != second_blob[:12]
    assert evidence.dec(first) == evidence.dec(second) == "new evidence"
    assert evidence.enc(first) == first


def test_hex_ciphertext_authentication_and_wrong_key(key, monkeypatch):
    stored = evidence.enc("authenticated evidence")
    key_id, encoded = stored[len('enc:v2:'):].split(':', 1)
    blob = bytearray.fromhex(encoded)
    blob[-1] ^= 1
    with pytest.raises(evidence.EvidenceKeyError, match='cannot be decrypted'):
        evidence.dec('enc:v2:' + key_id + ':' + blob.hex())
    monkeypatch.setattr(evidence, "_key_cache", bytes(reversed(key)))
    with pytest.raises(evidence.EvidenceKeyError, match='cannot be decrypted'):
        evidence.dec(stored)
