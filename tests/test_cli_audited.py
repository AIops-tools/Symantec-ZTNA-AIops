"""CLI delegates to governed MCP twin functions."""

from typer.testing import CliRunner


def test_cli_delegates(monkeypatch):
    from symantec_ztna_aiops import cli

    calls = []

    def fake(limit):
        calls.append(limit)
        return {"sample": {}, "partial": False}

    monkeypatch.setattr(cli.ztna, "ztna_health_sample", fake)
    result = CliRunner().invoke(cli.app, ["health-sample", "--limit", "50"])
    assert result.exit_code == 0
    assert calls == [50]


def test_cli_failure_is_not_empty_success(monkeypatch):
    from symantec_ztna_aiops import cli

    monkeypatch.setattr(cli.ztna, "ztna_sites", lambda *a: {"error": "HTTP 503"})
    result = CliRunner().invoke(cli.app, ["sites"])
    assert result.exit_code == 1
    assert "HTTP 503" in result.output
