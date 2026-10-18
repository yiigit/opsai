import json

import pytest

from opsai.infrastructure import osv


def test_refresh_queries_and_paginates_then_writes_full_advisories(tmp_path, monkeypatch):
    calls = []

    def fake_request(url, payload=None, **_kwargs):
        calls.append((url, payload))
        if url == osv.OSV_QUERY_BATCH_URL:
            query = payload['queries'][0]
            if 'page_token' not in query:
                return {
                    'results': [{
                        'vulns': [{'id': 'OSV-Z'}],
                        'next_page_token': 'next-page',
                    }],
                }
            assert query['page_token'] == 'next-page'
            return {'results': [{'vulns': [{'id': 'OSV-A'}]}]}
        identifier = url.rsplit('/', 1)[-1]
        return {'id': identifier, 'affected': []}

    monkeypatch.setattr(osv, '_request_json', fake_request)
    output = tmp_path / 'osv-packagist.json'
    count = osv.refresh_osv_snapshot([('vendor/package', '1.2.3')], output)

    assert count == 2
    assert json.loads(output.read_text()) == {
        'vulns': [
            {'id': 'OSV-A', 'affected': []},
            {'id': 'OSV-Z', 'affected': []},
        ],
    }
    assert calls[0][1]['queries'][0] == {
        'package': {'name': 'vendor/package', 'ecosystem': 'Packagist'},
        'version': '1.2.3',
    }
    assert len(calls) == 4


def test_refresh_empty_lock_writes_valid_empty_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(
        osv,
        '_request_json',
        lambda *_args, **_kwargs: pytest.fail('No request is needed for an empty lockfile'),
    )
    output = tmp_path / 'osv-packagist.json'
    assert osv.refresh_osv_snapshot([], output) == 0
    assert json.loads(output.read_text()) == {'vulns': []}


def test_refresh_failure_preserves_existing_snapshot_and_cleans_temp_file(tmp_path, monkeypatch):
    output = tmp_path / 'osv-packagist.json'
    output.write_text('existing snapshot', encoding='utf-8')

    def fail_request(*_args, **_kwargs):
        raise OSError('offline')

    monkeypatch.setattr(osv, '_request_json', fail_request)
    with pytest.raises(OSError, match='offline'):
        osv.refresh_osv_snapshot([('vendor/package', '1.2.3')], output)
    assert output.read_text() == 'existing snapshot'
    assert list(tmp_path.iterdir()) == [output]


def test_refresh_rejects_too_many_packages_before_network(tmp_path, monkeypatch):
    monkeypatch.setattr(
        osv,
        '_request_json',
        lambda *_args, **_kwargs: pytest.fail('Package limit must be checked before network access'),
    )
    packages = [('vendor/package', '1.0.0')] * (osv.MAX_PACKAGES + 1)
    with pytest.raises(ValueError, match='package OSV refresh limit'):
        osv.refresh_osv_snapshot(packages, tmp_path / 'snapshot.json')


def test_refresh_requires_existing_output_directory_before_network(tmp_path, monkeypatch):
    monkeypatch.setattr(
        osv,
        '_request_json',
        lambda *_args, **_kwargs: pytest.fail('Invalid output path must be checked before network'),
    )
    with pytest.raises(ValueError, match='output directory must already exist'):
        osv.refresh_osv_snapshot([], tmp_path / 'missing' / 'snapshot.json')


def test_refresh_rejects_mismatched_batch_response(tmp_path, monkeypatch):
    monkeypatch.setattr(osv, '_request_json', lambda *_args, **_kwargs: {'results': []})
    with pytest.raises(ValueError, match='invalid querybatch response'):
        osv.refresh_osv_snapshot(
            [('vendor/package', '1.0.0')],
            tmp_path / 'snapshot.json',
        )


def test_refresh_rejects_symlink_output(tmp_path, monkeypatch):
    target = tmp_path / 'target.json'
    target.write_text('keep', encoding='utf-8')
    output = tmp_path / 'snapshot.json'
    output.symlink_to(target)
    monkeypatch.setattr(
        osv,
        '_request_json',
        lambda *_args, **_kwargs: pytest.fail('Must reject a symlink before network access'),
    )
    with pytest.raises(ValueError, match='symbolic link'):
        osv.refresh_osv_snapshot([], output)
    assert target.read_text() == 'keep'
