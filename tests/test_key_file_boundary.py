"""Current-key boundaries and sanitized failures, using synthetic keys only."""
import base64
import os
import traceback
from pathlib import Path
from unittest.mock import Mock

import pytest

from aegis import config, evidence


@pytest.fixture
def key_boundary(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config, "DATA_DIR", data)
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", "")
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY_FILE", "")
    monkeypatch.setattr(evidence, "_key_cache", None)
    return data, base64.urlsafe_b64encode(os.urandom(32)).decode()


@pytest.mark.parametrize("location", ["relative-inside", "outside-symlink-inside"])
def test_unsafe_key_file_refused_before_read(key_boundary, tmp_path, monkeypatch, location):
    data, raw = key_boundary
    target = data / "synthetic.key"
    target.write_text(raw)
    if location == "relative-inside":
        configured = Path("data") / target.name
    else:
        configured = tmp_path / "outside.key"
        configured.symlink_to(target)
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY_FILE", str(configured))
    read = Mock(side_effect=lambda *a, **kw: pytest.fail("unsafe key file read before refusal"))
    monkeypatch.setattr(Path, "read_text", read)

    with pytest.raises(evidence.EvidenceKeyError):
        evidence._load_key()

    read.assert_not_called()
    assert evidence._key_cache is None


@pytest.mark.parametrize("failure", ["io", "text-decode", "key-decode"])
def test_key_file_errors_are_sanitized(key_boundary, tmp_path, monkeypatch, failure):
    _, raw = key_boundary
    path = tmp_path / "private-synthetic.key"
    path.write_text(raw)
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY_FILE", str(path))
    detail = f"private failure {path} {raw}"
    if failure == "io":
        monkeypatch.setattr(Path, "read_text", Mock(side_effect=OSError(detail)))
    elif failure == "text-decode":
        monkeypatch.setattr(Path, "read_text", Mock(side_effect=UnicodeDecodeError(
            "utf-8", b"\xff", 0, 1, detail)))
    else:
        monkeypatch.setattr(base64, "urlsafe_b64decode", Mock(side_effect=ValueError(detail)))

    with pytest.raises(evidence.EvidenceKeyError) as caught:
        evidence._load_key()

    error = caught.value
    rendered = "".join(traceback.format_exception(error))
    for private in (str(path), raw, "private failure"):
        assert private not in str(error)
        assert private not in rendered
    assert error.__cause__ is None
    assert error.__context__ is None or error.__suppress_context__
    assert evidence._key_cache is None


def test_env_key_takes_precedence_over_unsafe_file(key_boundary, monkeypatch):
    data, raw = key_boundary
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", raw)
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY_FILE", str(data / "never-read.key"))
    read = Mock(side_effect=lambda *a, **kw: pytest.fail("env key must bypass file reads"))
    monkeypatch.setattr(Path, "read_text", read)

    assert evidence._load_key() == base64.urlsafe_b64decode(raw)
    read.assert_not_called()


def test_external_relative_key_file_supported(key_boundary, monkeypatch):
    _, raw = key_boundary
    path = Path("external-synthetic.key")
    path.write_text(raw + "\n")
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY_FILE", str(path))

    assert evidence._load_key() == base64.urlsafe_b64decode(raw)
