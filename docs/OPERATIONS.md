# Operations catalog

All listed operations are read-only and route through the same audited MCP/CLI implementation. A tool count describes interface coverage, not live verification.

## Tenant and connectivity

| MCP tool | Purpose |
|---|---|
| `ztna_health_sample` | Sample site, connector and application health with partial probe errors. |
| `ztna_sites` | List one page of tenant sites. |
| `ztna_site` | Read one site. |
| `ztna_site_status` | Read connector health for one site. |
| `ztna_regions` | List connectivity regions. |
| `ztna_region` | Read one ZTNA region. |
| `ztna_connectors` | List one page of connectors. |
| `ztna_connector` | Read one connector and its state. |
| `ztna_connector_version` | Read the tenant latest connector version. |
| `ztna_connector_metrics` | Read bounded connector utilization metrics. |

## Applications and policies

| MCP tool | Purpose |
|---|---|
| `ztna_applications` | List one page of applications. |
| `ztna_application` | Read one application. |
| `ztna_application_status` | Read one application health state. |
| `ztna_policies` | List one page of access policies. |
| `ztna_policy` | Read one access policy. |
| `ztna_application_policies` | List policies assigned to an application. |
| `ztna_policy_condition_definitions` | Read policy condition schema. |
| `ztna_policy_action_types` | List policy action types. |
| `ztna_policy_validator_types` | List policy validator types. |
| `ztna_shared_objects` | List shared policy objects. |
| `ztna_shared_object` | Read one shared policy object. |

## Collections and DNS

| MCP tool | Purpose |
|---|---|
| `ztna_collections` | List site collections. |
| `ztna_collection` | Read one site collection. |
| `ztna_site_collections` | Read collections linked to a site. |
| `ztna_role_bindings` | List tenant and collection role bindings. |
| `ztna_dns_groups` | List DNS resiliency groups. |
| `ztna_dns_group` | Read DNS group health and failover status. |
| `ztna_dns_servers` | List DNS servers in a group. |
| `ztna_dns_server` | Read DNS server health. |

## Identity

| MCP tool | Purpose |
|---|---|
| `ztna_identity_providers` | List configured identity providers. |
| `ztna_users` | Search users with an opaque provider cursor. |
| `ztna_user` | Read one user identity. |
| `ztna_groups` | Search groups with an opaque provider cursor. |
| `ztna_group` | Read one identity group. |
| `ztna_group_users` | List assigned group users. |
| `ztna_blocked_users` | List blocked identities. |
| `ztna_ssh_clients` | List SSH clients. |

## Integrations and audit

| MCP tool | Purpose |
|---|---|
| `ztna_cloud_integrations` | List cloud integrations and health. |
| `ztna_cloud_integration` | Read one cloud integration. |
| `ztna_audit_logs` | Search bounded tenant audit logs with an explicit cursor. |

## Limits and next work

Site registration keys and connector environment variables can expose credentials. Forensic-log search needs a separate privacy review; configuration writes need live result and undo proof.

API paths and response examples are from the official Broadcom documentation listed below. No tenant or appliance has been supplied for live verification; consult [VERIFICATION.md](VERIFICATION.md).

- [ztna_sites](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_sites.md)
- [ztna_connectors](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_connectors.md)
- [ztna_apps](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_apps.md)
- [ztna_policies](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_policies.md)
- [ztna_shared_objects](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_shared_objects.md)
- [ztna_collections](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_collections.md)
- [ztna_dns](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_dns.md)
- [ztna_idps](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_idps.md)
- [ztna_users](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_users.md)
- [ztna_groups](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_groups.md)
- [ztna_ssh](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_ssh.md)
- [ztna_cloud_integ](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_cloud_integ.md)
- [ztna_audit](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_audit.md)
