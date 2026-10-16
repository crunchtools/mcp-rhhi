# Claude Code Instructions

Read-only MCP server for the Hummingbird / Red Hat Hardened Images catalog API, 12 tools across 4 categories. The API is public; no credentials.

## Quick Start

```bash
# uvx (recommended)
claude mcp add mcp-rhhi-crunchtools -- uvx mcp-rhhi-crunchtools

# Container
claude mcp add mcp-rhhi-crunchtools -- podman run -i --rm quay.io/crunchtools/mcp-rhhi

# Local development
cd ~/Projects/crunchtools/mcp-rhhi
claude mcp add mcp-rhhi-crunchtools -- uv run mcp-rhhi-crunchtools
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RHHI_API_URL` | No | `https://api-hummingbird.hummingbird-project.io` | Catalog API base URL |
| `RHHI_TIMEOUT` | No | `30` | Request timeout in seconds |

## Available Tools (12)

| Category | Tools | Operations |
|----------|-------|------------|
| Images | 2 | list, get (with README) |
| Tags | 3 | list, container details, SBOM |
| Vulnerabilities | 3 | per tag, catalog-wide, find CVE |
| Releases | 4 | history, details, SBOM, CVEs by digest |

Full tool inventory with API endpoints: `.specify/specs/000-baseline/spec.md`

## API Gotchas

- Release endpoints take the digest hex without the `sha256:` prefix; `digest_segment()` strips it.
- `/v1/vulnerabilities` `cves[].affected` is a list of integer indices into `tags[]`, not tag names.
- Severities come back title case (`Critical`); tools compare lowercase.
- Responses are gzip; httpx decodes them.

## Development

```bash
uv sync --all-extras          # Install dependencies
uv run ruff check src tests   # Lint
uv run mypy src               # Type check
uv run pytest -v              # Tests (mocked)
```

Quality gates and architecture: `.specify/memory/constitution.md`
