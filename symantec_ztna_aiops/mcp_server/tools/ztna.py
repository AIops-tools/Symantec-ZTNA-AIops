"""Governed ZTNA tenant read tools."""

from typing import Optional

from symantec_ztna_aiops import ops
from symantec_ztna_aiops.connection import get_connection
from symantec_ztna_aiops.governance import governed_tool
from symantec_ztna_aiops.mcp_server._shared import mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_sites(limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    """[READ] List one page of tenant sites."""
    return ops.sites(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_site(site_id: str) -> dict:
    """[READ] Read one site."""
    return ops.site(get_connection(), site_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_site_status(site_id: str) -> dict:
    """[READ] Read connector health for one site."""
    return ops.site_status(get_connection(), site_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_regions(limit: int = 100) -> dict:
    """[READ] List connectivity regions."""
    return ops.regions(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_connectors(limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    """[READ] List one page of connectors."""
    return ops.connectors(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_connector(connector_id: str) -> dict:
    """[READ] Read one connector and its state."""
    return ops.connector(get_connection(), connector_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_connector_version() -> dict:
    """[READ] Read the tenant latest connector version."""
    return ops.connector_version(get_connection())


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_applications(limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    """[READ] List one page of applications."""
    return ops.applications(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_application(application_id: str) -> dict:
    """[READ] Read one application."""
    return ops.application(get_connection(), application_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_application_status(application_id: str) -> dict:
    """[READ] Read one application health state."""
    return ops.application_status(get_connection(), application_id)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_policies(limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    """[READ] List one page of access policies."""
    return ops.policies(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_policy(policy_id: str) -> dict:
    """[READ] Read one access policy."""
    return ops.policy(get_connection(), policy_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_application_policies(application_id: str, limit: int = 100) -> dict:
    """[READ] List policies assigned to an application."""
    return ops.application_policies(get_connection(), application_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_connector_metrics(
    site_id: str, start_ms: int, end_ms: int, metric: str, step: int = 300
) -> dict:
    """[READ] Read bounded connector utilization metrics."""
    return ops.connector_metrics(get_connection(), site_id, start_ms, end_ms, metric, step)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["free_text"])
@tool_errors()
def ztna_audit_logs(
    start_ms: int,
    end_ms: int,
    limit: int = 100,
    free_text: str = "",
    cursor_time: Optional[int] = None,
    cursor_id: Optional[str] = None,
) -> dict:
    """[READ] Search bounded tenant audit logs with an explicit cursor."""
    return ops.audit_logs(
        get_connection(), start_ms, end_ms, limit, free_text, cursor_time, cursor_id
    )


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_health_sample(limit: int = 20) -> dict:
    """[READ] Sample site, connector and application health with partial probe errors."""
    return ops.health_sample(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_shared_objects(limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    """[READ] List shared policy objects."""
    return ops.shared_objects(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_shared_object(object_id: str) -> dict:
    """[READ] Read one shared policy object."""
    return ops.shared_object(get_connection(), object_id)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_collections(limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    """[READ] List site collections."""
    return ops.collections(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_collection(collection_id: str) -> dict:
    """[READ] Read one site collection."""
    return ops.collection(get_connection(), collection_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_site_collections(site_id: str) -> dict:
    """[READ] Read collections linked to a site."""
    return ops.site_collections(get_connection(), site_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_role_bindings(limit: int = 50, page: int = 0) -> dict:
    """[READ] List tenant and collection role bindings."""
    return ops.role_bindings(get_connection(), limit, page)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_dns_groups(limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    """[READ] List DNS resiliency groups."""
    return ops.dns_groups(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_dns_group(group_id: str) -> dict:
    """[READ] Read DNS group health and failover status."""
    return ops.dns_group(get_connection(), group_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_dns_servers(group_id: str, limit: int = 100) -> dict:
    """[READ] List DNS servers in a group."""
    return ops.dns_servers(get_connection(), group_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_dns_server(group_id: str, server_id: str) -> dict:
    """[READ] Read DNS server health."""
    return ops.dns_server(get_connection(), group_id, server_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_identity_providers(include_local: bool = False, limit: int = 100) -> dict:
    """[READ] List configured identity providers."""
    return ops.identity_providers(get_connection(), include_local, limit)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_users(
    provider_id: str, limit: int = 25, page_offset: str = "", filter_text: str = ""
) -> dict:
    """[READ] Search users with an opaque provider cursor."""
    return ops.users(get_connection(), provider_id, limit, page_offset, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_user(provider_id: str, user_id: str) -> dict:
    """[READ] Read one user identity."""
    return ops.user(get_connection(), provider_id, user_id)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_groups(
    provider_id: str, limit: int = 25, page_offset: str = "", filter_text: str = ""
) -> dict:
    """[READ] Search groups with an opaque provider cursor."""
    return ops.groups(get_connection(), provider_id, limit, page_offset, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_group(provider_id: str, group_id: str) -> dict:
    """[READ] Read one identity group."""
    return ops.group(get_connection(), provider_id, group_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_group_users(
    provider_id: str, group_id: str, limit: int = 25, page_offset: str = ""
) -> dict:
    """[READ] List assigned group users."""
    return ops.group_users(get_connection(), provider_id, group_id, limit, page_offset)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_blocked_users(limit: int = 100) -> dict:
    """[READ] List blocked identities."""
    return ops.blocked_users(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_ssh_clients(limit: int = 50, page: int = 0, filter_text: str = "") -> dict:
    """[READ] List SSH clients."""
    return ops.ssh_clients(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_cloud_integrations(limit: int = 100) -> dict:
    """[READ] List cloud integrations and health."""
    return ops.cloud_integrations(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_cloud_integration(integration_id: str) -> dict:
    """[READ] Read one cloud integration."""
    return ops.cloud_integration(get_connection(), integration_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_policy_condition_definitions() -> dict:
    """[READ] Read policy condition schema."""
    return ops.policy_condition_definitions(get_connection())


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_policy_action_types(limit: int = 100) -> dict:
    """[READ] List policy action types."""
    return ops.policy_action_types(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_policy_validator_types(limit: int = 100) -> dict:
    """[READ] List policy validator types."""
    return ops.policy_validator_types(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_region(region_name: str) -> dict:
    """[READ] Read one ZTNA region."""
    return ops.region(get_connection(), region_name)
