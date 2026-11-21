"""Synthetic identity and durability boundaries."""
import hashlib
import os
from pathlib import Path
import runpy
import stat

import pytest
from aegis import audit, config


@pytest.mark.parametrize('alias', ['relative', 'parent', 'directory_symlink', 'db_symlink', 'hardlink'])
def test_startup_refuses_alias_without_writes(tmp_path, monkeypatch, alias):
    root = tmp_path.resolve()
    data = root / 'data'
    data.mkdir()
    database = data / 'aegis.db'
    database.write_bytes(b'synthetic history')
    selected = data
    if alias == 'relative':
        monkeypatch.chdir(root)
        selected = Path('data')
    elif alias == 'parent':
        selected = root / 'unused' / '..' / 'data'
    elif alias == 'directory_symlink':
        selected = root / 'alias'
        selected.symlink_to(data, target_is_directory=True)
    elif alias == 'db_symlink':
        selected = root / 'other'
        selected.mkdir()
        (selected / 'aegis.db').symlink_to(database)
    else:
        os.link(database, root / 'linked.db')
    monkeypatch.setenv('AEGIS_DATA_DIR', str(selected))
    with pytest.raises(ValueError, match='Database path unsupported') as refused:
        runpy.run_path(config.__file__)
    assert str(root) not in str(refused.value)
    assert database.read_bytes() == b'synthetic history'
    assert not (data / 'anchors').exists()
    assert not (selected / 'recordings').exists()
    assert not Path(str(database) + '.audit.lock').exists()


def test_canonical_startup_preserves_identity(tmp_path, monkeypatch):
    data = tmp_path.resolve() / 'new'
    monkeypatch.setenv('AEGIS_DATA_DIR', str(data))
    loaded = runpy.run_path(config.__file__)
    assert loaded['DB_PATH'] == data / 'aegis.db'
    monkeypatch.setattr(config, 'DB_PATH', loaded['DB_PATH'])
    assert audit._stream_id() == hashlib.sha256(str(data / 'aegis.db').encode()).hexdigest()[:12]


def test_publication_rejects_late_hardlink(tmp_path, monkeypatch):
    database = tmp_path.resolve() / 'aegis.db'
    database.write_bytes(b'synthetic')
    os.link(database, tmp_path / 'linked.db')
    monkeypatch.setattr(config, 'DB_PATH', database)
    with pytest.raises(ValueError, match='Database path unsupported'):
        with audit.publication_lock():
            pytest.fail('unsupported identity acquired lock')
    assert not Path(str(database) + '.audit.lock').exists()


def test_legacy_key_durable_before_use(tmp_path, monkeypatch):
    key = tmp_path / 'synthetic.key'
    monkeypatch.setattr(audit, '_KEY_FILE', key)
    synced = []
    original = os.fsync
    def sync(fd):
        synced.append((stat.S_ISDIR(os.fstat(fd).st_mode), stat.S_IMODE(os.fstat(fd).st_mode)))
        original(fd)
    monkeypatch.setattr(os, 'fsync', sync)
    first = audit._signing_key()
    assert synced == [(False, 0o600), (True, stat.S_IMODE(key.parent.stat().st_mode))]
    assert audit._signing_key() == first
    assert len(synced) == 2


def test_checkpoint_parent_fsync(monkeypatch):
    synced = []
    original = os.fsync
    def sync(fd):
        synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        original(fd)
    monkeypatch.setattr(os, 'fsync', sync)
    monkeypatch.setattr(audit, '_write_external_anchor', lambda *args: None)
    audit.record('synthetic_durability', {})
    assert synced == [False, True]
