import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from core.exceptions import IntegrityError
from modules.module_b_disk.evidence import external_output, inventory, verify_hashes, working_copy
from modules.module_b_disk.recover_evidence import _open_ro, analyze_profile, main


def manifest(root, names):
    (root / 'hashes.sha256').write_text(''.join(
        f'{hashlib.sha256((root / name).read_bytes()).hexdigest()}  ./{name}\n'
        for name in names
    ))


def test_nested_manifest_and_duplicate_basenames(tmp_path):
    for folder, content in [('a', b'one'), ('b', b'two')]:
        (tmp_path / folder).mkdir()
        (tmp_path / folder / 'same file').write_bytes(content)
    manifest(tmp_path, ['a/same file', 'b/same file'])
    result = verify_hashes(tmp_path)
    assert set(result) == {'a/same file', 'b/same file'}
    assert all(v['status'] == 'match' for v in result.values())


@pytest.mark.parametrize('name', ['db.sqlite', 'db.sqlite-wal', 'db.sqlite-shm'])
def test_all_mismatches_block_analysis(tmp_path, name):
    (tmp_path / name).write_bytes(b'original')
    manifest(tmp_path, [name])
    (tmp_path / name).write_bytes(b'changed')
    with pytest.raises(IntegrityError, match='Manifest verification failed'):
        analyze_profile(tmp_path)


@pytest.mark.parametrize('entry', ['garbage', '0' * 64 + '  ../escape',
                                  '0' * 64 + '  /etc/passwd', '0' * 64 + '  missing'])
def test_invalid_and_missing_entries_block(tmp_path, entry):
    (tmp_path / 'hashes.sha256').write_text(entry + '\n')
    with pytest.raises(IntegrityError):
        analyze_profile(tmp_path)


def test_symlink_rejected(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (tmp_path / 'external').write_text('outside')
    (source / 'link').symlink_to(tmp_path / 'external')
    with pytest.raises(IntegrityError, match='symbolic link'):
        analyze_profile(source)


def test_working_copy_detects_source_change(tmp_path):
    (tmp_path / 'file').write_text('initial')
    with pytest.raises(IntegrityError, match='changed during analysis'):
        with working_copy(tmp_path):
            (tmp_path / 'file').write_text('changed')


def test_wal_only_record_and_source_preservation(tmp_path):
    db = tmp_path / 'profile ?#.sqlite'
    writer = sqlite3.connect(db)
    try:
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute('PRAGMA wal_autocheckpoint=0')
        writer.execute('CREATE TABLE evidence(value TEXT)')
        writer.commit()
        writer.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        writer.execute("INSERT INTO evidence VALUES ('WAL-only record')")
        writer.commit()
        assert db.with_name(db.name + '-wal').stat().st_size > 0
        before = inventory(tmp_path)
        with _open_ro(db) as reader:
            assert reader.execute('SELECT value FROM evidence').fetchall() == [('WAL-only record',)]
        assert inventory(tmp_path) == before
        # Establish that the inserted row was not in the main database alone.
        main_only = tmp_path / 'main-only.sqlite'
        main_only.write_bytes(db.read_bytes())
        with _open_ro(main_only) as reader:
            assert reader.execute('SELECT value FROM evidence').fetchall() == []
    finally:
        writer.close()


def test_output_guards_and_incomplete_reporting(tmp_path, capsys):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'places.sqlite').write_bytes(b'corrupt database')
    before = inventory(source)
    assert main([str(source), '--out', str(source / 'report.json')]) == 1
    output = tmp_path / 'results' / 'report.json'
    assert main([str(source), '--out', str(output)]) == 2
    report = json.loads(output.read_text())
    assert report['analysis_status'] == 'incomplete'
    assert report['integrity']['manifest_status'] == 'absent'
    assert report['integrity']['source_unchanged'] is True
    assert 'error' in report['places']
    assert inventory(source) == before
    custody = json.loads(output.with_name('report.custody.json').read_text())
    assert custody[0]['artifact_path'] == str(source / 'places.sqlite')
    contents = output.read_bytes()
    assert main([str(source), '--out', str(output)]) == 1
    assert output.read_bytes() == contents
    assert 'Analysis incomplete' in capsys.readouterr().out


def test_output_symlink_into_evidence_rejected(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(source, target_is_directory=True)
    with pytest.raises(ValueError, match='outside'):
        external_output(alias / 'report.json', source)
