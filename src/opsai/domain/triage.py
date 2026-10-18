"""Pure, deterministic log sanitization and triage."""
import re
from collections import Counter

MAX_LINE_CHARS = 1200
# Conservative patterns: redact secrets before output, storage or API calls.
REDACTIONS = [
    (re.compile(r'(?i)\b(bearer\s+)\S+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)\b(authorization\s*[:=]\s*)(?!bearer\b)\S+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)\b((?:password|passwd|token|secret|api[_-]?key|client_secret|access_key|DB_PASSWORD|APP_KEY)\s*[:=]\s*)[\'\"]?[^\s,;\'\"]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)([?&](?:token|key|password|secret|api_key)=)[^&\s]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)\b([\w.+-]+)@([\w.-]+\.[a-z]{2,})'), '[EMAIL_REDACTED]'),
    (re.compile(r'(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP_REDACTED]'),
]


def redact(line: str) -> str:
    line = line[:MAX_LINE_CHARS]
    for pattern, replacement in REDACTIONS:
        line = pattern.sub(replacement, line)
    return line


def summarize(source: str, raw_lines: list[str]) -> dict:
    sanitized = [redact(line) for line in raw_lines]
    error_pattern = re.compile(r'(?i)\b(error|exception|critical|fatal|emergency|alert|failed|traceback)\b|\[error\]')
    warning_pattern = re.compile(r'(?i)\b(warn(?:ing)?|notice)\b')
    errors = [line for line in sanitized if error_pattern.search(line)]
    warnings = [line for line in sanitized if warning_pattern.search(line) and not error_pattern.search(line)]
    # Remove common timestamp and Laravel severity prefixes before grouping.
    def signature(line: str) -> str:
        line = re.sub(r'^\[\d{4}-\d{2}-\d{2}[^]]*\]\s*', '', line)
        line = re.sub(r'^\d{4}[-/]\d{2}[-/]\d{2}[T\s][\d:.+Z-]+\s*', '', line)
        line = re.sub(r'\b\d+\b', '<N>', line)
        line = re.sub(r'"[^"]*"', '"..."', line)
        return line[:180]

    signatures = Counter(signature(line) for line in errors)
    return {
        'source': source,
        'total_lines': len(sanitized),
        'error_lines': len(errors),
        'warning_lines': len(warnings),
        'top_errors': [{'signature': k, 'count': v} for k, v in signatures.most_common(5)],
        'sample': sanitized[-min(len(sanitized), 60):],
        'note': 'Heuristic classification; sample may contain sensitive information not caught by redaction.',
    }
