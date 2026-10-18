from opsai.collectors import health


def test_health_metrics():
    metrics = health()
    for key in ('cpu_percent', 'memory_percent', 'disk_percent'):
        assert 0 <= metrics[key] <= 100
    assert metrics['disk_free_gb'] >= 0
