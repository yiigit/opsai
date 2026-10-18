"""OWASP Top 10:2025 categories used by deterministic security checks."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OwaspCategory:
    id: str
    title: str


OWASP_TOP_10_2025 = (
    OwaspCategory('A01:2025', 'Broken Access Control'),
    OwaspCategory('A02:2025', 'Security Misconfiguration'),
    OwaspCategory('A03:2025', 'Software Supply Chain Failures'),
    OwaspCategory('A04:2025', 'Cryptographic Failures'),
    OwaspCategory('A05:2025', 'Injection'),
    OwaspCategory('A06:2025', 'Insecure Design'),
    OwaspCategory('A07:2025', 'Authentication Failures'),
    OwaspCategory('A08:2025', 'Software or Data Integrity Failures'),
    OwaspCategory('A09:2025', 'Security Logging and Alerting Failures'),
    OwaspCategory('A10:2025', 'Mishandling of Exceptional Conditions'),
)

_CATEGORIES_BY_ID = {category.id: category for category in OWASP_TOP_10_2025}


def get_owasp_category(category_id: str) -> OwaspCategory:
    """Return a known OWASP Top 10:2025 category."""
    try:
        return _CATEGORIES_BY_ID[category_id]
    except KeyError as exc:
        raise ValueError(f'Unknown OWASP Top 10:2025 category: {category_id}') from exc
