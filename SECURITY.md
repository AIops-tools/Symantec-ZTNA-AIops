# Security

Report vulnerabilities privately through GitHub security advisories. Do not include API client secrets, tenant logs, connector inventories or local audit databases in public issues.

Pass credentials through process environment from a secret manager. The tool never accepts credentials as MCP arguments and verifies TLS certificates by default; use `SYMANTEC_ZTNA_CA_BUNDLE` for a private CA. The vendored governance harness writes audit metadata and result summaries under `~/.symantec-ztna-aiops/` by default. Audit-search free text is redacted from local audit parameters, but responses delivered to an MCP client can contain sensitive user activity; scope the API client and MCP client accordingly.
