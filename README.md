<!-- mcp-name: io.github.AIops-tools/symantec-ztna-aiops -->

# Symantec ZTNA AIops

An independent MCP server, CLI and skill for **Symantec Zero Trust Network Access**. This preview exposes **40 governed read tools** for tenant and connector health, applications, access policies, shared objects, collections, DNS, identities, cloud integrations and audit logs. It is separate from SEP, SES Cloud and on-premises EDR.

> Community-maintained project. Not affiliated with or endorsed by Broadcom or Symantec; product names are their owners’ trademarks.

## Setup

Set `SYMANTEC_ZTNA_URL` to the tenant API HTTPS origin, such as `https://api.example.luminatesec.com`, and provide `SYMANTEC_ZTNA_CLIENT_ID` and `SYMANTEC_ZTNA_CLIENT_SECRET` from a ZTNA API client. The URL must be an origin without a path. Optional settings are `SYMANTEC_ZTNA_CA_BUNDLE`, `SYMANTEC_ZTNA_TIMEOUT` and `SYMANTEC_ZTNA_AIOPS_HOME` for local governance storage. Use an API client with the least privileges needed for the reads you intend to call.

Run `uv run symantec-ztna-aiops --help`. The MCP entry point is `symantec-ztna-aiops-mcp`. CLI commands mirror all MCP tools; see the [operations catalog](docs/OPERATIONS.md) for the full list and official API sources.

Paged endpoints return `truncated`, `nextPage` and `totalReported` from the documented server page metadata. Audit searches fetch one extra log to measure truncation and return the next `SearchAfterValues` cursor. Search windows are capped at 30 days; connector metrics at seven days. `health-sample` is explicitly a sample and reports partial probe failures. No state-changing API is exposed in this unverified preview.

See [verification](docs/VERIFICATION.md) for official API evidence and the remaining live-tenant checks. Missing a common ZTNA task? Open an issue or PR with the product version and a sanitized response shape.
