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
