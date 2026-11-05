# Verification

## Confirmed from official documentation

- [ZTNA overview](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_about.md) describes tenant API origins, `/v2/` resources and page-size maximum 100. [Authentication](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_auth.md) defines Basic client-credential exchange at `/v1/oauth/token` and a 60-minute bearer token.
- [Sites](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_sites.md), [connectors](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_connectors.md), [applications](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_apps.md) and [policies](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_policies.md) define the read resources and the `content`/`last`/`number`/`totalElements` page envelope.
- [Audit logs](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_audit.md) use query-only POST with `SearchAfterValues`; [connector utilization](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/ztna_observability.md) accepts a seven-day maximum window.

## Locally verified

- Contract-shaped HTTP mock tests cover OAuth Basic exchange and one 401 refresh, bad-login backoff, strict page metadata, query-only audit POST, measured truncation and cursor, TLS-origin validation, metric window limits and read-only endpoint allowlist.
- Local build review: 42 pytest tests passed; Ruff passed; Bandit reported 0 Medium+ findings. The wheel installed in a clean external virtual environment and its MCP server imported from site-packages with 16 tools.

## Unverified

- No live ZTNA tenant or client credentials have been supplied. Endpoint response shapes, privileges, audit pagination and utilization behavior remain unverified against a real tenant.
- No configuration write is exposed. Adding writes requires an independent end-to-end result and rollback verification.
