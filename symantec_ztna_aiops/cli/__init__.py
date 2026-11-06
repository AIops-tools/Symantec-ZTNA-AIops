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


@app.command("shared-objects")
def shared_objects(limit: int = 50, page: int = 0, filter_text: str = "") -> None:
    _emit(ztna.ztna_shared_objects(limit, page, filter_text))


@app.command("shared-object")
def shared_object(object_id: str) -> None:
    _emit(ztna.ztna_shared_object(object_id))


@app.command("collections")
def collections(limit: int = 50, page: int = 0, filter_text: str = "") -> None:
    _emit(ztna.ztna_collections(limit, page, filter_text))


@app.command("collection")
def collection(collection_id: str) -> None:
    _emit(ztna.ztna_collection(collection_id))


@app.command("site-collections")
def site_collections(site_id: str) -> None:
    _emit(ztna.ztna_site_collections(site_id))


@app.command("role-bindings")
def role_bindings(limit: int = 50, page: int = 0) -> None:
    _emit(ztna.ztna_role_bindings(limit, page))


@app.command("dns-groups")
def dns_groups(limit: int = 50, page: int = 0, filter_text: str = "") -> None:
    _emit(ztna.ztna_dns_groups(limit, page, filter_text))


@app.command("dns-group")
def dns_group(group_id: str) -> None:
    _emit(ztna.ztna_dns_group(group_id))


@app.command("dns-servers")
def dns_servers(group_id: str, limit: int = 100) -> None:
    _emit(ztna.ztna_dns_servers(group_id, limit))


@app.command("dns-server")
def dns_server(group_id: str, server_id: str) -> None:
    _emit(ztna.ztna_dns_server(group_id, server_id))


@app.command("identity-providers")
def identity_providers(include_local: bool = False, limit: int = 100) -> None:
    _emit(ztna.ztna_identity_providers(include_local, limit))


@app.command("users")
def users(provider_id: str, limit: int = 25, page_offset: str = "", filter_text: str = "") -> None:
    _emit(ztna.ztna_users(provider_id, limit, page_offset, filter_text))


@app.command("user")
def user(provider_id: str, user_id: str) -> None:
    _emit(ztna.ztna_user(provider_id, user_id))


@app.command("groups")
def groups(provider_id: str, limit: int = 25, page_offset: str = "", filter_text: str = "") -> None:
    _emit(ztna.ztna_groups(provider_id, limit, page_offset, filter_text))


@app.command("group")
def group(provider_id: str, group_id: str) -> None:
    _emit(ztna.ztna_group(provider_id, group_id))


@app.command("group-users")
def group_users(provider_id: str, group_id: str, limit: int = 25, page_offset: str = "") -> None:
    _emit(ztna.ztna_group_users(provider_id, group_id, limit, page_offset))


@app.command("blocked-users")
def blocked_users(limit: int = 100) -> None:
    _emit(ztna.ztna_blocked_users(limit))


@app.command("ssh-clients")
def ssh_clients(limit: int = 50, page: int = 0, filter_text: str = "") -> None:
    _emit(ztna.ztna_ssh_clients(limit, page, filter_text))


@app.command("cloud-integrations")
def cloud_integrations(limit: int = 100) -> None:
    _emit(ztna.ztna_cloud_integrations(limit))


@app.command("cloud-integration")
def cloud_integration(integration_id: str) -> None:
    _emit(ztna.ztna_cloud_integration(integration_id))


@app.command("policy-condition-definitions")
def policy_condition_definitions() -> None:
    _emit(ztna.ztna_policy_condition_definitions())


@app.command("policy-action-types")
def policy_action_types(limit: int = 100) -> None:
    _emit(ztna.ztna_policy_action_types(limit))


@app.command("policy-validator-types")
def policy_validator_types(limit: int = 100) -> None:
    _emit(ztna.ztna_policy_validator_types(limit))


@app.command("region")
def region(region_name: str) -> None:
    _emit(ztna.ztna_region(region_name))
