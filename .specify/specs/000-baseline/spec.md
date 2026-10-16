# Baseline Specification: mcp-rhhi-crunchtools

> **Spec ID:** 000-baseline
> **Status:** Implemented
> **Version:** 0.1.0

## Overview

mcp-rhhi-crunchtools is a read-only MCP server for the Hummingbird / Red Hat
Hardened Images catalog API (`https://api-hummingbird.hummingbird-project.io`,
OpenAPI at `/v1/openapi.json`). It replaces the curl-and-jq recipes in the
`/hummingbird` skill with tools any gateway profile can call.

## Tool Inventory

All tools are GET and annotated `readOnlyHint: true`.

### Images (2 tools)

| Tool | Endpoint | Description |
|------|----------|-------------|
| `list_images` | `/v1/images` | Compact rows; filter by text and category; returns the category list |
| `get_image` | `/v1/images/{name}` | Metadata; README stripped to text on request |

### Tags (3 tools)

| Tool | Endpoint | Description |
|------|----------|-------------|
| `list_tags` | `/v1/images/{name}/tags` | Non-superseded by default; filter stream, variant |
| `get_tag_details` | `/v1/images/{name}/details/{canonical}` | Container config and provenance per arch |
| `get_sbom` | `/v1/images/{name}/sbom/{canonical}` | Counts per arch; packages for one arch, filtered and capped |

### Vulnerabilities (3 tools)

| Tool | Endpoint | Description |
|------|----------|-------------|
| `get_tag_vulnerabilities` | `/v1/images/{name}/vulnerabilities/{canonical}` | Scan summary and CVEs at or above a severity |
| `get_catalog_vulnerabilities` | `/v1/vulnerabilities` | Catalog summary, per-image counts, top CVEs |
| `find_cve` | `/v1/vulnerabilities` | Images and tags an advisory affects |

### Releases (4 tools)

| Tool | Endpoint | Description |
|------|----------|-------------|
| `get_release_history` | `/v1/images/{name}/history/{stream}/{variant}` | Releases newest first, capped |
| `get_release_details` | `/v1/images/{name}/releases/details/{hex}` | Historical container config |
| `get_release_sbom` | `/v1/images/{name}/releases/sbom/{hex}` | Historical SBOM |
| `get_release_vulnerabilities` | `/v1/images/{name}/releases/vulnerabilities/{hex}` | Historical CVE scan |

## Response Shaping

The catalog returns whole documents (catalog CVEs ~500 KB, an SBOM ~100 KB).
Tools trim them: lists carry `matched` and `truncated`, CVE descriptions are
cut at 500 characters, SBOM packages default to amd64 and 100 rows, and the
catalog CVE feed's integer `affected` indices are joined back to
image/stream/variant/canonical.

## Out of Scope (v0.1)

- Caching of `/v1/vulnerabilities` between calls
- Source-repository lookups (`gitlab.com/redhat/hummingbird/containers`)
