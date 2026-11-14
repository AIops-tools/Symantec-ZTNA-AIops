"""Governed ZTNA tenant read tools."""

from typing import Annotated, Optional

from pydantic import Field

from symantec_ztna_aiops import ops
from symantec_ztna_aiops.connection import get_connection
from symantec_ztna_aiops.governance import governed_tool
from symantec_ztna_aiops.mcp_server._shared import mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_sites(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 50,
    page: Annotated[int, Field(description="Zero-based upstream page number.")] = 0,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List one page of tenant sites.

    Use to discover IDs before calling ztna_site for a single resource.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.sites(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_site(site_id: Annotated[str, Field(description="Site ID from the site listing.")]) -> dict:
    """[READ] Read one site.

    Use for one known resource; call ztna_sites to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.site(get_connection(), site_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_site_status(
    site_id: Annotated[str, Field(description="Site ID from the site listing.")],
) -> dict:
    """[READ] Read connector health for one site.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.site_status(get_connection(), site_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_regions(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List connectivity regions.

    Use to discover IDs before calling ztna_region for a single resource.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.regions(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_connectors(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 50,
    page: Annotated[int, Field(description="Zero-based upstream page number.")] = 0,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List one page of connectors.

    Use to discover IDs before calling ztna_connector for a single resource.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.connectors(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_connector(
    connector_id: Annotated[str, Field(description="Connector ID from the connector listing.")],
) -> dict:
    """[READ] Read one connector and its state.

    Use for one known resource; call ztna_connectors to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
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
def ztna_application(
    application_id: Annotated[
        str, Field(description="Application ID from the application listing.")
    ],
) -> dict:
    """[READ] Read one application.

    Use for one known resource; call ztna_applications to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.application(get_connection(), application_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_application_status(
    application_id: Annotated[
        str, Field(description="Application ID from the application listing.")
    ],
) -> dict:
    """[READ] Read one application health state.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.application_status(get_connection(), application_id)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_policies(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 50,
    page: Annotated[int, Field(description="Zero-based upstream page number.")] = 0,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List one page of access policies.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.policies(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_policy(
    policy_id: Annotated[
        str, Field(description="Policy ID from the corresponding policy listing.")
    ],
) -> dict:
    """[READ] Read one access policy.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.policy(get_connection(), policy_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_application_policies(
    application_id: Annotated[
        str, Field(description="Application ID from the application listing.")
    ],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List policies assigned to an application.

    Use for policies attached to one application; use ztna_policies for tenant policy inventory.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.application_policies(get_connection(), application_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_connector_metrics(
    site_id: Annotated[str, Field(description="Site ID from the site listing.")],
    start_ms: Annotated[
        int, Field(description=("Start of the query window in Unix epoch milliseconds."))
    ],
    end_ms: Annotated[
        int, Field(description=("End time in Unix epoch milliseconds; after start_ms."))
    ],
    metric: Annotated[
        str,
        Field(description=("Connector-utilization metric identifier accepted by the tenant API.")),
    ],
    step: Annotated[
        int, Field(description=("Metric sample interval in seconds (60–43200); defaults to 300."))
    ] = 300,
) -> dict:
    """[READ] Read bounded connector utilization metrics.

    Use for a time-bounded connector-utilization series at one site; use ztna_connector for a
    connector’s current state.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.connector_metrics(get_connection(), site_id, start_ms, end_ms, metric, step)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["free_text"])
@tool_errors()
def ztna_audit_logs(
    start_ms: Annotated[
        int, Field(description=("Start of the query window in Unix epoch milliseconds."))
    ],
    end_ms: Annotated[
        int, Field(description=("End time in Unix epoch milliseconds; after start_ms."))
    ],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 100,
    free_text: Annotated[
        str, Field(description="Optional bounded tenant audit-log search text.")
    ] = "",
    cursor_time: Annotated[
        Optional[int],
        Field(
            description=(
                "Continuation timestamp from the preceding audit-log page; pair with cursor_id."
            )
        ),
    ] = None,
    cursor_id: Annotated[
        Optional[str],
        Field(
            description=(
                "Continuation ID from the preceding audit-log page; pair with cursor_time."
            )
        ),
    ] = None,
) -> dict:
    """[READ] Search bounded tenant audit logs with an explicit cursor.

    Use for time-bounded tenant audit events; use resource detail tools for current
    configuration.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.audit_logs(
        get_connection(), start_ms, end_ms, limit, free_text, cursor_time, cursor_id
    )


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_health_sample(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum records sampled per category (1–100)."
            )
        ),
    ] = 20,
) -> dict:
    """[READ] Sample site, connector and application health with partial probe errors.

    Use for a bounded cross-resource sample; use site, connector or application status tools for
    a specific resource.

    Result: sample, errors, partial and sampleLimit; failed probes leave that category null.
    """
    return ops.health_sample(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_shared_objects(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 50,
    page: Annotated[int, Field(description="Zero-based upstream page number.")] = 0,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List shared policy objects.

    Use to discover IDs before calling ztna_shared_object for a single resource.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.shared_objects(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_shared_object(
    object_id: Annotated[str, Field(description="Shared policy-object ID from the listing.")],
) -> dict:
    """[READ] Read one shared policy object.

    Use for one known resource; call ztna_shared_objects to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.shared_object(get_connection(), object_id)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_collections(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 50,
    page: Annotated[int, Field(description="Zero-based upstream page number.")] = 0,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List site collections.

    Use to discover IDs before calling ztna_collection for a single resource.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.collections(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_collection(
    collection_id: Annotated[str, Field(description="Site-collection ID from the listing.")],
) -> dict:
    """[READ] Read one site collection.

    Use for one known resource; call ztna_collections to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.collection(get_connection(), collection_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_site_collections(
    site_id: Annotated[str, Field(description="Site ID from the site listing.")],
) -> dict:
    """[READ] Read collections linked to a site.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.site_collections(get_connection(), site_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_role_bindings(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 50,
    page: Annotated[int, Field(description="Zero-based upstream page number.")] = 0,
) -> dict:
    """[READ] List tenant and collection role bindings.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.role_bindings(get_connection(), limit, page)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_dns_groups(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 50,
    page: Annotated[int, Field(description="Zero-based upstream page number.")] = 0,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List DNS resiliency groups.

    Use to discover IDs before calling ztna_dns_group for a single resource.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
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
def ztna_dns_servers(
    group_id: Annotated[str, Field(description="Group ID from the corresponding listing.")],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List DNS servers in a group.

    Use to discover IDs before calling ztna_dns_server for a single resource.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.dns_servers(get_connection(), group_id, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_dns_server(
    group_id: Annotated[str, Field(description="Group ID from the corresponding listing.")],
    server_id: Annotated[
        str, Field(description=("DNS server ID within the selected DNS resiliency group."))
    ],
) -> dict:
    """[READ] Read DNS server health.

    Use for one known resource; call ztna_dns_servers to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.dns_server(get_connection(), group_id, server_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_identity_providers(
    include_local: Annotated[
        bool, Field(description="Include the tenant-local identity provider when true.")
    ] = False,
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List configured identity providers.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.identity_providers(get_connection(), include_local, limit)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_users(
    provider_id: Annotated[
        str, Field(description=("Identity-provider ID that scopes this user or group lookup."))
    ],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 25,
    page_offset: Annotated[
        str,
        Field(
            description=(
                "Opaque provider continuation token from the preceding page; empty starts a search."
            )
        ),
    ] = "",
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] Search users with an opaque provider cursor.

    Use to discover IDs before calling ztna_user for a single resource.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.users(get_connection(), provider_id, limit, page_offset, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_user(
    provider_id: Annotated[
        str, Field(description=("Identity-provider ID that scopes this user or group lookup."))
    ],
    user_id: Annotated[str, Field(description="User ID within the selected identity provider.")],
) -> dict:
    """[READ] Read one user identity.

    Use for one known resource; call ztna_users to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.user(get_connection(), provider_id, user_id)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_groups(
    provider_id: Annotated[
        str, Field(description=("Identity-provider ID that scopes this user or group lookup."))
    ],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 25,
    page_offset: Annotated[
        str,
        Field(
            description=(
                "Opaque provider continuation token from the preceding page; empty starts a search."
            )
        ),
    ] = "",
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] Search groups with an opaque provider cursor.

    Use to discover IDs before calling ztna_group for a single resource.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.groups(get_connection(), provider_id, limit, page_offset, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_group(
    provider_id: Annotated[
        str, Field(description=("Identity-provider ID that scopes this user or group lookup."))
    ],
    group_id: Annotated[str, Field(description="Group ID from the corresponding listing.")],
) -> dict:
    """[READ] Read one identity group.

    Use for one known resource; call ztna_groups to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.group(get_connection(), provider_id, group_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_group_users(
    provider_id: Annotated[
        str, Field(description=("Identity-provider ID that scopes this user or group lookup."))
    ],
    group_id: Annotated[str, Field(description="Group ID from the corresponding listing.")],
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 25,
    page_offset: Annotated[
        str,
        Field(
            description=(
                "Opaque provider continuation token from the preceding page; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] List assigned group users.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.group_users(get_connection(), provider_id, group_id, limit, page_offset)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_blocked_users(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List blocked identities.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.blocked_users(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["filter_text"])
@tool_errors()
def ztna_ssh_clients(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 50,
    page: Annotated[int, Field(description="Zero-based upstream page number.")] = 0,
    filter_text: Annotated[
        str, Field(description=("Optional upstream filter expression; bounded by the operation."))
    ] = "",
) -> dict:
    """[READ] List SSH clients.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.ssh_clients(get_connection(), limit, page, filter_text)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_cloud_integrations(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List cloud integrations and health.

    Use to discover IDs before calling ztna_cloud_integration for a single resource.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.cloud_integrations(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_cloud_integration(
    integration_id: Annotated[str, Field(description="Cloud-integration ID from the listing.")],
) -> dict:
    """[READ] Read one cloud integration.

    Use for one known resource; call ztna_cloud_integrations to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.cloud_integration(get_connection(), integration_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_policy_condition_definitions() -> dict:
    """[READ] Read policy condition schema.

    Use before constructing a policy condition, to discover the tenant's supported fields.
    Result: definitions, or an explicit operation error.
    """
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
def ztna_policy_validator_types(
    limit: Annotated[
        int,
        Field(
            description=(
                "Maximum rows to include (1–100)."
            )
        ),
    ] = 100,
) -> dict:
    """[READ] List policy validator types.

    Result: bounded results with truncation or continuation metadata when the endpoint provides
    it.
    """
    return ops.policy_validator_types(get_connection(), limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def ztna_region(
    region_name: Annotated[
        str, Field(description="Region name from the connectivity-region listing.")
    ],
) -> dict:
    """[READ] Read one ZTNA region.

    Use for one known resource; call ztna_regions to discover IDs.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.region(get_connection(), region_name)
