# mcp-rhhi-crunchtools Constitution

> **Version:** 1.0.0
> **Ratified:** 2026-10-16
> **Status:** Active
> **Inherits:** [crunchtools/constitution](https://github.com/crunchtools/constitution) v1.28.0
> **Profile:** MCP Server

This file holds what is specific to mcp-rhhi. The fleet rules and the MCP
Server profile apply at the inherited version and are checked against this
repo's files by `constitution.yml`. They are not restated here.

## Security Model Specifics

- **Credentials:** none. The Hummingbird catalog API is public and
  unauthenticated, so there is no `SecretStr`, no `_FILE` variant and no
  token scrubbing. Should the API ever need a token, Layer 1 applies in full
  before it ships.
- **Input limits:** every parameter is constrained in the published schema.
  Image, stream, variant, canonical and arch names match
  `^[A-Za-z0-9][A-Za-z0-9._-]*$` (1-128); digests `^(sha256:)?[a-fA-F0-9]{64}$`;
  advisory IDs `^[A-Za-z]{2,5}-[A-Za-z0-9-]{4,40}$`; severities and SBOM
  categories are enums. `segment()` and `digest_segment()` re-check before a
  value reaches a URL.
- **API:** TLS verified; `RHHI_TIMEOUT` (default 30s); responses capped at 20MB;
  error text capped at 200 characters.
- **Surface:** every tool is a GET and is annotated `readOnlyHint`.

## Instance

| Context | Name |
|---------|------|
| GitHub repo | `crunchtools/mcp-rhhi` |
| PyPI package | `mcp-rhhi-crunchtools` |
| Container image | `quay.io/crunchtools/mcp-rhhi` |
| systemd service | `mcp-rhhi.crunchtools.com.service` |
| HTTP port | 8030 |

| Variable | Default |
|----------|---------|
| `RHHI_API_URL` | `https://api-hummingbird.hummingbird-project.io` |
| `RHHI_TIMEOUT` | `30` |

## History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-10-16 | Initial constitution |
