import pytest

from riskscope.config import Settings


def test_defaults_to_localhost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RENDER_EXTERNAL_URL", raising=False)
    monkeypatch.delenv("RISKSCOPE_PUBLIC_BASE_URL", raising=False)
    s = Settings(_env_file=None)
    assert s.public_base_url == "http://127.0.0.1:8000" and s.is_local


def test_uses_render_url_and_blank_values_fall_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://riskscope.onrender.com")
    monkeypatch.setenv("RISKSCOPE_PUBLIC_BASE_URL", "  ")
    monkeypatch.setenv("RISKSCOPE_SMTP_FROM", "")
    s = Settings(_env_file=None)
    assert s.public_base_url == "https://riskscope.onrender.com" and not s.is_local
    assert s.smtp_from == "riskscope <no-reply@localhost>"


def test_explicit_url_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://riskscope.onrender.com")
    monkeypatch.setenv("RISKSCOPE_PUBLIC_BASE_URL", "https://scan.example.org")
    assert Settings(_env_file=None).public_base_url == "https://scan.example.org"


def test_codespaces_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RENDER_EXTERNAL_URL", raising=False)
    monkeypatch.delenv("RISKSCOPE_PUBLIC_BASE_URL", raising=False)
    monkeypatch.setenv("CODESPACE_NAME", "fluffy-spoon-x7")
    monkeypatch.setenv("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN", "app.github.dev")
    s = Settings(_env_file=None)
    assert s.public_base_url == "https://fluffy-spoon-x7-8000.app.github.dev" and not s.is_local
