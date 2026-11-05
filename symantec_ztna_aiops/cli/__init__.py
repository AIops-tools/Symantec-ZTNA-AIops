"""CLI commands use the same governed ZTNA tools as MCP."""

from __future__ import annotations

import json

import typer

from symantec_ztna_aiops.governance import BudgetExceeded
from symantec_ztna_aiops.mcp_server.tools import ztna

app = typer.Typer(name="symantec-ztna-aiops", no_args_is_help=True)


def governed(result: dict) -> dict:
    if result.get("outcomeUnknown"):
        typer.echo(json.dumps(result, ensure_ascii=False))
        raise typer.Exit(2)
    if result.get("error"):
        typer.echo(json.dumps(result, ensure_ascii=False), err=True)
        raise typer.Exit(1)
    return result


def _emit(result: dict) -> None:
    typer.echo(json.dumps(governed(result), ensure_ascii=False, indent=2))


@app.command("sites")
def sites(limit: int = 50, page: int = 0, filter_text: str = "") -> None:
    _emit(ztna.ztna_sites(limit, page, filter_text))


@app.command("site")
def site(site_id: str) -> None:
    _emit(ztna.ztna_site(site_id))


@app.command("site-status")
def site_status(site_id: str) -> None:
    _emit(ztna.ztna_site_status(site_id))


@app.command("regions")
def regions(limit: int = 100) -> None:
    _emit(ztna.ztna_regions(limit))


@app.command("connectors")
def connectors(limit: int = 50, page: int = 0, filter_text: str = "") -> None:
    _emit(ztna.ztna_connectors(limit, page, filter_text))


@app.command("connector")
def connector(connector_id: str) -> None:
    _emit(ztna.ztna_connector(connector_id))


@app.command("connector-version")
def connector_version() -> None:
    _emit(ztna.ztna_connector_version())


@app.command("applications")
def applications(limit: int = 50, page: int = 0, filter_text: str = "") -> None:
    _emit(ztna.ztna_applications(limit, page, filter_text))


@app.command("application")
def application(application_id: str) -> None:
    _emit(ztna.ztna_application(application_id))


@app.command("application-status")
def application_status(application_id: str) -> None:
    _emit(ztna.ztna_application_status(application_id))


@app.command("policies")
def policies(limit: int = 50, page: int = 0, filter_text: str = "") -> None:
    _emit(ztna.ztna_policies(limit, page, filter_text))


@app.command("policy")
def policy(policy_id: str) -> None:
    _emit(ztna.ztna_policy(policy_id))


@app.command("application-policies")
def application_policies(application_id: str, limit: int = 100) -> None:
    _emit(ztna.ztna_application_policies(application_id, limit))


@app.command("connector-metrics")
def connector_metrics(
    site_id: str, start_ms: int, end_ms: int, metric: str, step: int = 300
) -> None:
    _emit(ztna.ztna_connector_metrics(site_id, start_ms, end_ms, metric, step))


@app.command("audit-logs")
def audit_logs(
    start_ms: int,
    end_ms: int,
    limit: int = 100,
    free_text: str = "",
    cursor_time: int | None = None,
    cursor_id: str | None = None,
) -> None:
    _emit(ztna.ztna_audit_logs(start_ms, end_ms, limit, free_text, cursor_time, cursor_id))


@app.command("health-sample")
def health_sample(limit: int = 20) -> None:
    _emit(ztna.ztna_health_sample(limit))


def main() -> None:
    try:
        app()
    except BudgetExceeded as exc:
        typer.echo(f"Budget stopped the operation: {exc}", err=True)
        raise typer.Exit(1) from exc
