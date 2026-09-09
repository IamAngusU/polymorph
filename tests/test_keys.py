from __future__ import annotations

import os

import pytest

from polymorph.errors import IntegrityError
from polymorph.keys import EncryptedRecipientKeyFile, KeyFileParameters


FAST = KeyFileParameters(memory_cost_kib=8 * 1024, iterations=1, lanes=1)


def test_encrypted_recipient_key_roundtrip(tmp_path) -> None:
    path = tmp_path / "recipient.key"
    public = EncryptedRecipientKeyFile.create(path, "a-long-test-passphrase", params=FAST)
    assert EncryptedRecipientKeyFile.public_key(path) == public
    private = EncryptedRecipientKeyFile.load(path, "a-long-test-passphrase")
    assert EncryptedRecipientKeyFile.validate(path, "a-long-test-passphrase") == public
    assert b"PRIVATE KEY" not in path.read_bytes()
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0
    assert private is not None


def test_encrypted_recipient_key_wrong_passphrase_fails(tmp_path) -> None:
    path = tmp_path / "recipient.key"
    EncryptedRecipientKeyFile.create(path, "correct-passphrase-123", params=FAST)
    with pytest.raises(IntegrityError, match="authentication failed"):
        EncryptedRecipientKeyFile.load(path, "wrong-passphrase-456")


def test_encrypted_recipient_key_detects_metadata_tampering(tmp_path) -> None:
    path = tmp_path / "recipient.key"
    EncryptedRecipientKeyFile.create(path, "correct-passphrase-123", params=FAST)
    text = path.read_text(encoding="utf-8")
    text = text.replace('"lanes": 1', '"lanes": 2')
    path.write_text(text, encoding="utf-8")
    with pytest.raises(IntegrityError):
        EncryptedRecipientKeyFile.load(path, "correct-passphrase-123")
