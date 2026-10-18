"""Bounded client for refreshing project-specific snapshots from OSV.dev."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

OSV_QUERY_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/'
REQUEST_TIMEOUT_SECONDS = 15
MAX_REFRESH_SECONDS = 180
MAX_PACKAGES = 1_000
MAX_ADVISORIES = 1_000
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 50 * 1024 * 1024
QUERY_BATCH_SIZE = 100


def _request_json(
    url: str,
    payload: dict[str, Any] | None = None,
    *,
    deadline: float,
) -> Any:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f'OSV refresh exceeded the {MAX_REFRESH_SECONDS}-second time limit')
    body = json.dumps(payload).encode('utf-8') if payload is not None else None
    request = Request(
        url,
        data=body,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': 'opsai-cli',
        },
        method='POST' if body is not None else 'GET',
    )
    try:
        with urlopen(request, timeout=min(REQUEST_TIMEOUT_SECONDS, remaining)) as response:
            content = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise OSError(f'OSV.dev returned HTTP {exc.code} for {url}') from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise OSError(f'OSV.dev request failed for {url}: {exc}') from exc
    if len(content) > MAX_RESPONSE_BYTES:
        raise ValueError(f'OSV.dev response exceeds the {MAX_RESPONSE_BYTES}-byte limit')
    try:
        return json.loads(content.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError('OSV.dev returned invalid UTF-8 JSON') from exc


def _vulnerability_ids(packages: list[tuple[str, str]], deadline: float) -> set[str]:
    if not packages:
        return set()
    if len(packages) > MAX_PACKAGES:
        raise ValueError(f'Composer lockfile exceeds the {MAX_PACKAGES}-package OSV refresh limit')

    queries = [
        {
            'package': {'name': name, 'ecosystem': 'Packagist'},
            'version': version,
        }
        for name, version in packages
    ]
    vulnerability_ids: set[str] = set()
    for offset in range(0, len(queries), QUERY_BATCH_SIZE):
        page_queries = queries[offset:offset + QUERY_BATCH_SIZE]
        while page_queries:
            response = _request_json(
                OSV_QUERY_BATCH_URL,
                {'queries': page_queries},
                deadline=deadline,
            )
            results = response.get('results') if isinstance(response, dict) else None
            if not isinstance(results, list) or len(results) != len(page_queries):
                raise ValueError('OSV.dev returned an invalid querybatch response')
            next_page: list[dict[str, Any]] = []
            for query, result in zip(page_queries, results):
                if not isinstance(result, dict):
                    raise ValueError('OSV.dev querybatch results must be objects')
                records = result.get('vulns', [])
                if not isinstance(records, list):
                    raise ValueError('OSV.dev querybatch vulnerabilities must be an array')
                for record in records:
                    identifier = record.get('id') if isinstance(record, dict) else None
                    if not isinstance(identifier, str) or not identifier or len(identifier) > 128:
                        raise ValueError('OSV.dev querybatch returned an invalid vulnerability id')
                    vulnerability_ids.add(identifier)
                    if len(vulnerability_ids) > MAX_ADVISORIES:
                        raise ValueError(
                            f'OSV.dev result exceeds the {MAX_ADVISORIES}-advisory refresh limit'
                        )
                token = result.get('next_page_token')
                if token is not None:
                    if not isinstance(token, str) or not token or len(token) > 2_048:
                        raise ValueError('OSV.dev returned an invalid pagination token')
                    next_page.append({**query, 'page_token': token})
            page_queries = next_page
    return vulnerability_ids


def _fetch_advisories(
    packages: list[tuple[str, str]],
    deadline: float,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    snapshot_size = 0
    for identifier in sorted(_vulnerability_ids(packages, deadline)):
        encoded_id = quote(identifier, safe='')
        advisory = _request_json(f'{OSV_VULN_URL}{encoded_id}', deadline=deadline)
        if (
            not isinstance(advisory, dict)
            or advisory.get('id') != identifier
            or not isinstance(advisory.get('affected'), list)
        ):
            raise ValueError(f'OSV.dev returned an invalid advisory for {identifier}')
        snapshot_size += len(json.dumps(advisory, ensure_ascii=False).encode('utf-8')) + 1
        if snapshot_size > MAX_SNAPSHOT_BYTES:
            raise ValueError(f'OSV snapshot exceeds the {MAX_SNAPSHOT_BYTES}-byte size limit')
        records.append(advisory)
    return records


def refresh_osv_snapshot(
    packages: list[tuple[str, str]],
    output_path: Path,
) -> int:
    """Fetch matching advisories and atomically write an OSV-compatible JSON snapshot."""
    if not output_path.parent.is_dir():
        raise ValueError('OSV snapshot output directory must already exist')
    if output_path.is_symlink():
        raise ValueError('OSV snapshot output must not be a symbolic link')
    if output_path.exists() and not output_path.is_file():
        raise ValueError('OSV snapshot output must be a regular file')

    deadline = time.monotonic() + MAX_REFRESH_SECONDS
    payload = {'vulns': _fetch_advisories(packages, deadline)}
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n'
    if len(rendered.encode('utf-8')) > MAX_SNAPSHOT_BYTES:
        raise ValueError(f'OSV snapshot exceeds the {MAX_SNAPSHOT_BYTES}-byte size limit')

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            dir=output_path.parent,
            prefix=f'.{output_path.name}.',
            suffix='.tmp',
            delete=False,
        ) as temporary:
            temporary.write(rendered)
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return len(payload['vulns'])
