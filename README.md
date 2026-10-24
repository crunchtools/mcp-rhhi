# MCP RHHI CrunchTools

A secure, read-only MCP (Model Context Protocol) server for the [Hummingbird](https://gitlab.com/redhat/hummingbird/containers) / Red Hat Hardened Images catalog. It wraps the public catalog API at `https://api-hummingbird.hummingbird-project.io` so an agent can find minimal, distroless images, pick the right tag, and check its container config, SBOM and CVEs without scraping anything.

## Overview

- **Read-only** - every tool is a GET against the catalog and publishes `readOnlyHint: true`
- **No credentials** - the catalog API is public; there is nothing to leak
- **Trimmed responses** - the catalog-wide CVE feed is ~500 KB and an SBOM ~100 KB; tools filter and cap server-side so an agent gets the answer, not the dump
- **Containerized** - `quay.io/crunchtools/mcp-rhhi`, built on the Hummingbird Python image it describes

## Naming Convention

| Component | Name |
|-----------|------|
| GitHub repo | [crunchtools/mcp-rhhi](https://github.com/crunchtools/mcp-rhhi) |
| Container | `quay.io/crunchtools/mcp-rhhi` |
| Python package (PyPI) | `mcp-rhhi-crunchtools` |
| CLI command | `mcp-rhhi-crunchtools` |
| Module import | `mcp_rhhi_crunchtools` |

## Key Concepts

- **Image name** - short identifier used in every call (`python`, `nodejs`, `aspnet-runtime`)
- **Stream** - version family within an image (`3.14`, `24`, `latest`)
- **Variant** - `default` (distroless, production), `builder` (adds bash, dnf, shadow-utils), `fips`, and image-specific ones
- **Canonical tag** - version-pinned tag used by the detail, SBOM and CVE tools (`3.14.8`, `3.14.8-builder`)
- **Superseded** - a tag replaced by a newer one in its stream+variant; hidden unless asked for

## Tools (14)

### Images
- `list_images` - all images with streams, variants and pull URL; filter by text or category
- `get_image` - one image's metadata, optionally its README as plain text

### Tags
- `list_tags` - current tags with `pull_url`, `digest`, `canonical`, sizes; filter by stream and variant
- `get_tag_details` - user, entrypoint, cmd, env, ports, Containerfile, source commit, SLSA level, per arch
- `get_sbom` - package counts per arch and a filterable package list

### Vulnerabilities
- `get_tag_vulnerabilities` - CVE scan for one tag, filterable by minimum severity
- `get_catalog_vulnerabilities` - catalog-wide stats over every current tag, with per-image counts
- `find_cve` - which current images and tags a CVE, GHSA or GO advisory affects

### Release history
- `get_release_history` - past releases of a stream+variant (digest, date, source commit)
- `get_release_details`, `get_release_sbom`, `get_release_vulnerabilities` - the same views for a historical digest

### Image requests
- `list_image_requests` - requests for new images on [images.redhat.com/image-requests](https://images.redhat.com/image-requests); filter by status or a title/key substring
- `get_image_request` - one request by HUM key or image title; returns status, status note and the public `deep_link`

Each request includes its HUM key, title, friendly status (Submitted / In progress / Delivered / Declined) and a `deep_link` of the form `https://images.redhat.com/image-requests?request=REQ-NNNN` that opens it on the site. (The site resolves the public `REQ-` alias; the API's underlying Jira key keeps the `HUM-` prefix with the same number.)

## Installation

```bash
# uvx
claude mcp add mcp-rhhi-crunchtools -- uvx mcp-rhhi-crunchtools

# pip
pip install mcp-rhhi-crunchtools

# Container
claude mcp add mcp-rhhi-crunchtools -- podman run -i --rm quay.io/crunchtools/mcp-rhhi

# HTTP (streamable-http)
podman run -d -p 127.0.0.1:8030:8030 quay.io/crunchtools/mcp-rhhi \
    --transport streamable-http --host 0.0.0.0 --port 8030
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RHHI_API_URL` | No | `https://api-hummingbird.hummingbird-project.io` | Catalog API base URL; HTTPS required except for localhost |
| `RHHI_REQUESTS_API_URL` | No | request gateway behind images.redhat.com | Image-request API base URL (a separate gateway from the catalog); HTTPS required except for localhost |
| `RHHI_SITE_URL` | No | `https://images.redhat.com` | Public site base URL used to build image-request deep links |
| `RHHI_TIMEOUT` | No | `30` | Request timeout in seconds (max 300) |

## Example Usage

```
Which Hummingbird image should I use for a Go service, and what are the builder and runtime pull URLs?
Does the python 3.14 image ship openssl, and which version?
Which images are affected by CVE-2025-12781?
Show critical and high CVEs across the catalog
What user and entrypoint does nodejs 24 run with?
```

## Security

See [SECURITY.md](SECURITY.md). In short: every parameter is validated against a published pattern before it reaches a URL, path segments are URL-encoded, TLS is verified, requests time out, and responses are capped at 20 MB.

## Development

```bash
uv sync --all-extras
uv run ruff check src tests
uv run mypy src
uv run pytest -v
podman run --rm -v .:/src:Z -w /src quay.io/crunchtools/gourmand:latest check --full
```

## License

AGPL-3.0-or-later

## Links

- [Catalog API (Swagger)](https://api-hummingbird.hummingbird-project.io/v1/docs/)
- [Hummingbird containers](https://gitlab.com/redhat/hummingbird/containers)
- [FastMCP Documentation](https://gofastmcp.com/)
- [crunchtools.com](https://crunchtools.com)

<!-- mcp-name: io.github.crunchtools/rhhi -->
