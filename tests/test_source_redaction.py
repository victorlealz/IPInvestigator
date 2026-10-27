from core.sources import _redact_url, _safe_error


def test_redact_url_query_secret():
    url = _redact_url("https://example.test/path?token=super-secret&x=1")
    assert "super-secret" not in url
    assert "token=REDACTED" in url


def test_safe_error_redacts_embedded_query_secret(monkeypatch):
    monkeypatch.setenv("IPINFO_TOKEN", "very-secret-token")
    exc = RuntimeError("failed url https://ipinfo.io/8.8.8.8/json?token=very-secret-token")
    msg = _safe_error(exc)
    assert "very-secret-token" not in msg
    assert "REDACTED" in msg
