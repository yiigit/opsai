"""Offline Laravel configuration and Composer dependency assessment."""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from functools import total_ordering
from pathlib import Path
from typing import Any

from opsai.domain.owasp import get_owasp_category

MAX_COMPOSER_LOCK_BYTES = 20 * 1024 * 1024
MAX_OSV_DATABASE_BYTES = 50 * 1024 * 1024
MAX_LARAVEL_ENV_BYTES = 1024 * 1024
MAX_ADVISORY_TEXT_LENGTH = 2000
SEVERITIES = ('critical', 'high', 'medium', 'low', 'unknown')


class UnsupportedOsvData(ValueError):
    """A valid assessment input uses a range or version format we do not compare."""


@dataclass(frozen=True)
class AppSecFinding:
    id: str
    severity: str
    title: str
    evidence: str
    recommendation: str
    source: str
    owasp: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _finding(
    identifier: str,
    severity: str,
    title: str,
    evidence: str,
    recommendation: str,
    category_id: str,
    source: str,
) -> AppSecFinding:
    category = get_owasp_category(category_id)
    return AppSecFinding(
        id=identifier,
        severity=severity,
        title=title,
        evidence=evidence,
        recommendation=recommendation,
        source=source,
        owasp={'id': category.id, 'title': category.title},
    )


def _read_json_file(path: Path, max_bytes: int, description: str) -> Any:
    try:
        with path.open('rb') as stream:
            content = stream.read(max_bytes + 1)
    except OSError as exc:
        raise OSError(f'Cannot access {description}: {path}') from exc
    if len(content) > max_bytes:
        raise ValueError(f'{description} exceeds the {max_bytes}-byte size limit')
    try:
        return json.loads(content.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f'{description} must be valid UTF-8 JSON') from exc


def _read_laravel_env(path: Path) -> tuple[dict[str, str], list[AppSecFinding]]:
    findings: list[AppSecFinding] = []
    if path.is_symlink():
        raise ValueError('Laravel .env must not be a symbolic link')
    if not path.exists():
        return {}, findings
    if not path.is_file():
        raise ValueError('Laravel .env must be a regular file')
    try:
        with path.open('rb') as stream:
            content_bytes = stream.read(MAX_LARAVEL_ENV_BYTES + 1)
    except OSError as exc:
        raise OSError('Cannot inspect Laravel .env file') from exc
    if len(content_bytes) > MAX_LARAVEL_ENV_BYTES:
        raise ValueError(f'Laravel .env exceeds the {MAX_LARAVEL_ENV_BYTES}-byte size limit')

    try:
        content = content_bytes.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError('Laravel .env must be valid UTF-8 text') from exc

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator:
            continue
        key = key.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        if key in values:
            raise ValueError(f'Laravel .env contains duplicate key {key!r} at line {line_number}')
        values[key] = value

    if os.name == 'posix':
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError as exc:
            raise OSError('Cannot inspect Laravel .env permissions') from exc
        if mode & 0o077:
            findings.append(_finding(
                'LARAVEL_ENV_PERMISSIONS', 'high',
                'Laravel .env is accessible by group or other users',
                'Laravel .env has group/other permission bits enabled.',
                'Restrict .env permissions to the deployment account; use a mode such as 0600 where appropriate.',
                'A02:2025', 'Laravel .env permissions',
            ))
    return values, findings


def audit_laravel_project(project: Path) -> list[AppSecFinding]:
    """Check a Laravel project and its local environment without exposing values."""
    if not project.is_dir():
        raise ValueError('Laravel project path must be a directory')
    composer_json_path = project / 'composer.json'
    artisan_path = project / 'artisan'
    if not artisan_path.is_file() or not composer_json_path.is_file():
        raise ValueError('Project must contain Laravel artisan and composer.json files')
    composer_json = _read_json_file(composer_json_path, MAX_COMPOSER_LOCK_BYTES, 'composer.json')
    if not isinstance(composer_json, dict):
        raise ValueError('composer.json must contain a JSON object')
    requirements: dict[str, Any] = {}
    for section in ('require', 'require-dev'):
        section_value = composer_json.get(section, {})
        if not isinstance(section_value, dict):
            raise ValueError(f'composer.json {section} must contain an object')
        requirements.update(section_value)
    if not any(str(name).lower() == 'laravel/framework' for name in requirements):
        raise ValueError('composer.json does not declare laravel/framework')

    env, findings = _read_laravel_env(project / '.env')
    production = env.get('APP_ENV', '').strip().lower() == 'production'

    if production:
        if env.get('APP_DEBUG', '').strip().lower() in ('true', '1', 'yes', 'on'):
            findings.append(_finding(
                'LARAVEL_DEBUG_PRODUCTION', 'high',
                'Laravel debug mode is enabled in production',
                'APP_DEBUG is enabled while APP_ENV is production.',
                'Disable APP_DEBUG in production and verify the deployed configuration cache.',
                'A02:2025', 'Laravel .env configuration',
            ))

        app_key = env.get('APP_KEY', '').strip()
        if not app_key or app_key.lower() in ('changeme', 'your-app-key', 'base64:changeme'):
            findings.append(_finding(
                'LARAVEL_APP_KEY_MISSING', 'high',
                'Laravel production application key is missing or a placeholder',
                'APP_KEY is empty or matches a common placeholder.',
                'Generate and securely provision a unique application key; do not commit the key.',
                'A04:2025', 'Laravel .env configuration',
            ))

        secure_cookie = env.get('SESSION_SECURE_COOKIE', '').strip().lower()
        if secure_cookie in ('false', '0', 'no', 'off'):
            findings.append(_finding(
                'LARAVEL_SESSION_COOKIE_SECURE', 'medium',
                'Laravel session cookies are configured without the Secure flag',
                'SESSION_SECURE_COOKIE is false in production.',
                'Enable secure session cookies when the application is served over HTTPS.',
                'A02:2025', 'Laravel .env configuration',
            ))
        if env.get('SESSION_HTTP_ONLY', '').strip().lower() in ('false', '0', 'no', 'off'):
            findings.append(_finding(
                'LARAVEL_SESSION_HTTP_ONLY', 'medium',
                'Laravel session cookies are configured without HttpOnly',
                'SESSION_HTTP_ONLY is false in production.',
                'Enable HttpOnly for session cookies unless a documented application requirement prevents it.',
                'A02:2025', 'Laravel .env configuration',
            ))
        same_site = env.get('SESSION_SAME_SITE', '').strip().lower()
        if same_site == 'none' and secure_cookie not in ('true', '1', 'yes', 'on'):
            findings.append(_finding(
                'LARAVEL_SESSION_SAMESITE', 'medium',
                'Laravel SameSite=None session cookies are not explicitly secure',
                'SESSION_SAME_SITE is none and SESSION_SECURE_COOKIE is not true.',
                'Set SESSION_SECURE_COOKIE=true when using SameSite=None over HTTPS.',
                'A02:2025', 'Laravel .env configuration',
            ))
    return findings


@total_ordering
@dataclass(frozen=True)
class _Version:
    release: tuple[int, int, int, int]
    prerelease: tuple[str, ...]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _Version):
            return NotImplemented
        if self.release != other.release:
            return self.release < other.release
        if not self.prerelease:
            return bool(other.prerelease)
        if not other.prerelease:
            return False
        for left, right in zip(self.prerelease, other.prerelease):
            if left == right:
                continue
            left_numeric = left.isdigit()
            right_numeric = right.isdigit()
            if left_numeric and right_numeric:
                return int(left) < int(right)
            if left_numeric != right_numeric:
                return left_numeric
            return left < right
        return len(self.prerelease) < len(other.prerelease)


_VERSION_PATTERN = re.compile(
    r'^v?(?P<release>\d+(?:\.\d+){0,3})'
    r'(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
    r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$',
    re.IGNORECASE,
)


def _parse_version(value: str) -> _Version:
    if len(value) > 128:
        raise UnsupportedOsvData('Unsupported Composer/OSV version syntax (value exceeds 128 characters)')
    match = _VERSION_PATTERN.fullmatch(value.strip())
    if not match:
        raise UnsupportedOsvData(f'Unsupported Composer/OSV version syntax: {value[:128]!r}')
    parts = tuple(int(part) for part in match.group('release').split('.'))
    release = (parts + (0, 0, 0, 0))[:4]
    prerelease = tuple(match.group('pre').split('.')) if match.group('pre') else ()
    if any(part.isdigit() and len(part) > 1 and part.startswith('0') for part in prerelease):
        raise UnsupportedOsvData(f'Unsupported Composer/OSV version syntax: {value[:128]!r}')
    return _Version(release, prerelease)


def _validate_composer_lock(payload: Any) -> list[tuple[str, str]]:
    if not isinstance(payload, dict):
        raise ValueError('composer.lock must contain a JSON object')
    packages: list[tuple[str, str]] = []
    seen: set[str] = set()
    for section in ('packages', 'packages-dev'):
        entries = payload.get(section, [])
        if not isinstance(entries, list):
            raise ValueError(f'composer.lock {section} must contain an array')
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError(f'composer.lock {section} entries must be objects')
            name, version = item.get('name'), item.get('version')
            if (
                not isinstance(name, str)
                or not name.strip()
                or len(name) > 255
                or not isinstance(version, str)
                or not version.strip()
                or len(version) > 128
            ):
                raise ValueError(f'composer.lock {section} entries need package name and version strings')
            normalized_name = name.strip().lower()
            if normalized_name in seen:
                raise ValueError(f'composer.lock contains duplicate package {normalized_name!r}')
            seen.add(normalized_name)
            packages.append((normalized_name, version.strip()))
    return packages


def load_composer_lock_packages(composer_lock: Path) -> list[tuple[str, str]]:
    """Load normalized package names and versions from a bounded Composer lockfile."""
    return _validate_composer_lock(
        _read_json_file(composer_lock, MAX_COMPOSER_LOCK_BYTES, 'composer.lock')
    )


def _load_osv_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get('vulns'), list):
        records: Any = payload['vulns']
    elif isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict) and isinstance(payload.get('affected'), list):
        records = [payload]
    else:
        raise ValueError('OSV snapshot must be an advisory object, an array, or an object with a vulns array')
    if any(not isinstance(record, dict) for record in records):
        raise ValueError('OSV snapshot advisories must be objects')
    if len(records) > 200_000:
        raise ValueError('OSV snapshot contains too many advisories')
    return records


def _range_contains(version: str, ranges: Any) -> bool:
    if not isinstance(ranges, list):
        raise ValueError('OSV affected ranges must be an array')
    candidate = _parse_version(version)
    for version_range in ranges:
        if not isinstance(version_range, dict):
            raise ValueError('OSV version ranges must be objects')
        if version_range.get('type') != 'SEMVER':
            raise UnsupportedOsvData(f"Unsupported OSV range type: {version_range.get('type')!r}")
        events = version_range.get('events')
        if not isinstance(events, list) or not events:
            raise ValueError('OSV version range events must be a non-empty array')
        start: _Version | None = None
        includes = False
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                raise ValueError('OSV range events must contain exactly one boundary')
            event_name, boundary_text = next(iter(event.items()))
            if not isinstance(boundary_text, str):
                raise ValueError('OSV range boundaries must be strings')
            if event_name == 'introduced':
                if includes:
                    raise ValueError('OSV range introduced another interval before closing the previous one')
                boundary = _parse_version(boundary_text) if boundary_text else _Version((0, 0, 0, 0), ())
                start = boundary
                includes = True
            elif event_name in ('fixed', 'limit'):
                if not includes or start is None:
                    raise ValueError(f'OSV range event {event_name!r} has no introduced boundary')
                boundary = _parse_version(boundary_text)
                if includes and start is not None and start <= candidate < boundary:
                    return True
                includes = False
                start = None
            elif event_name == 'last_affected':
                if not includes or start is None:
                    raise ValueError("OSV range event 'last_affected' has no introduced boundary")
                boundary = _parse_version(boundary_text)
                if includes and start is not None and start <= candidate <= boundary:
                    return True
                includes = False
                start = None
            else:
                raise UnsupportedOsvData(f'Unsupported OSV range event: {event_name!r}')
        if includes and start is not None and start <= candidate:
            return True
    return False


def _is_affected(version: str, affected: dict[str, Any]) -> bool:
    exact_versions = affected.get('versions', [])
    if not isinstance(exact_versions, list) or any(not isinstance(item, str) for item in exact_versions):
        raise ValueError('OSV affected versions must be an array of strings')
    normalized = version.strip().removeprefix('v').lower()
    if any(item.strip().removeprefix('v').lower() == normalized for item in exact_versions):
        return True
    ranges = affected.get('ranges', [])
    if not isinstance(ranges, list):
        raise ValueError('OSV affected ranges must be an array')
    if ranges:
        return _range_contains(version, ranges)
    return False


def _severity(advisory: dict[str, Any]) -> str:
    database_specific = advisory.get('database_specific')
    if isinstance(database_specific, dict):
        value = database_specific.get('severity')
        if isinstance(value, str):
            normalized = value.lower()
            if normalized in SEVERITIES:
                return normalized
            if normalized == 'moderate':
                return 'medium'
    severity_entries = advisory.get('severity', [])
    if isinstance(severity_entries, list):
        for entry in severity_entries:
            if not isinstance(entry, dict):
                continue
            score = entry.get('score')
            if isinstance(score, str):
                try:
                    numeric_score = float(score)
                except ValueError:
                    continue
                if 0 <= numeric_score <= 10:
                    if numeric_score >= 9:
                        return 'critical'
                    if numeric_score >= 7:
                        return 'high'
                    if numeric_score >= 4:
                        return 'medium'
                    if numeric_score > 0:
                        return 'low'
    return 'unknown'


def _advisory_summary(advisory: dict[str, Any]) -> str:
    summary = advisory.get('summary')
    if not isinstance(summary, str) or not summary.strip():
        summary = advisory.get('id', 'Vulnerability advisory')
    return ' '.join(summary.split())[:MAX_ADVISORY_TEXT_LENGTH]


def scan_composer_dependencies(composer_lock: Path, osv_database: Path) -> tuple[list[AppSecFinding], list[str]]:
    """Match Composer lockfile versions against a local OSV Packagist snapshot."""
    database_payload = _read_json_file(osv_database, MAX_OSV_DATABASE_BYTES, 'OSV snapshot')
    packages = load_composer_lock_packages(composer_lock)
    advisories = _load_osv_records(database_payload)
    package_versions = dict(packages)
    findings: list[AppSecFinding] = []
    errors: list[str] = []
    seen_findings: set[tuple[str, str]] = set()

    for advisory in advisories:
        advisory_id = advisory.get('id')
        affected_entries = advisory.get('affected')
        if not isinstance(advisory_id, str) or not advisory_id.strip() or len(advisory_id) > 128:
            raise ValueError('OSV advisories must have a non-empty id')
        if not isinstance(affected_entries, list):
            raise ValueError(f'OSV advisory {advisory_id} needs an affected array')
        summary = _advisory_summary(advisory)
        for affected in affected_entries:
            package = affected.get('package') if isinstance(affected, dict) else None
            package_name = package.get('name') if isinstance(package, dict) else None
            ecosystem = package.get('ecosystem') if isinstance(package, dict) else None
            if (
                not isinstance(package_name, str)
                or not package_name.strip()
                or len(package_name) > 255
                or not isinstance(ecosystem, str)
                or not ecosystem.strip()
                or len(ecosystem) > 80
            ):
                raise ValueError(f'OSV advisory {advisory_id} has an invalid affected package')
            if ecosystem.lower() != 'packagist':
                continue
            package_name = package_name.lower()
            locked_version = package_versions.get(package_name)
            if locked_version is None:
                continue
            try:
                vulnerable = _is_affected(locked_version, affected)
            except UnsupportedOsvData as exc:
                message = f'{advisory_id} / {package_name}: {exc}'
                errors.append(message)
                continue
            if not vulnerable:
                continue
            dedupe_key = (advisory_id, package_name)
            if dedupe_key in seen_findings:
                continue
            seen_findings.add(dedupe_key)
            aliases = advisory.get('aliases', [])
            alias_text = ', '.join(
                alias[:128] for alias in aliases[:5] if isinstance(alias, str)
            ) if isinstance(aliases, list) else ''
            title = f'{package_name} {locked_version}: {summary}'
            if alias_text:
                title = f'{title} ({alias_text[:300]})'
            findings.append(_finding(
                f'OSV-{advisory_id}',
                _severity(advisory),
                title[:MAX_ADVISORY_TEXT_LENGTH],
                f'composer.lock resolves {package_name} to an affected version {locked_version}.',
                'Review the local advisory details and update to a version outside the affected range.',
                'A03:2025', 'composer.lock / local OSV snapshot',
            ))
    return findings, errors


def assess_project(
    project: Path,
    *,
    osv_database: Path | None = None,
    skip_dependencies: bool = False,
) -> dict[str, Any]:
    """Create an offline Laravel and optional Composer dependency assessment."""
    project = project.resolve()
    if not project.is_dir():
        raise ValueError('Project path must be a directory')
    composer_lock = project / 'composer.lock'
    if osv_database is not None and skip_dependencies:
        raise ValueError('--osv-db cannot be combined with --skip-dependencies')
    if composer_lock.exists() and not skip_dependencies and osv_database is None:
        raise ValueError('composer.lock found; provide --osv-db or explicitly use --skip-dependencies')
    if osv_database is not None and not composer_lock.is_file():
        raise ValueError('composer.lock is required when --osv-db is provided')

    findings = audit_laravel_project(project)
    errors: list[str] = []
    checks = ['laravel_configuration']
    if osv_database is not None:
        dependency_findings, errors = scan_composer_dependencies(composer_lock, osv_database)
        findings.extend(dependency_findings)
        checks.append('composer_dependencies')

    counts = {severity: sum(item.severity == severity for item in findings) for severity in SEVERITIES}
    return {
        'schema_version': '1.0',
        'tool': 'opsai-appsec',
        'target': 'laravel',
        'project': project.name,
        'owasp_version': '2025',
        'checks': checks,
        'findings': [finding.as_dict() for finding in findings],
        'counts': counts,
        'errors': errors,
        'status': 'partial' if errors else 'completed',
    }


def gate_exit_code(report: dict[str, Any], threshold: str) -> int:
    if threshold not in (*SEVERITIES[:-1], 'none'):
        raise ValueError('Invalid severity threshold')
    if report.get('errors') or report.get('status') == 'partial':
        return 2
    if threshold != 'none' and report.get('counts', {}).get('unknown', 0):
        return 2
    if threshold != 'none' and any(
        finding['severity'] in SEVERITIES[:-1]
        and SEVERITIES.index(finding['severity']) <= SEVERITIES.index(threshold)
        for finding in report.get('findings', [])
    ):
        return 3
    return 0
