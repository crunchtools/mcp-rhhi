# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-11-08

### Added

- **The client says what it is.** Both clients — the catalog and the image
  request gateway — now send
  `User-Agent: mcp-rhhi-crunchtools/<version> (+<repo url>)`, with the version
  read from installed package metadata so it cannot drift from
  `pyproject.toml`. httpx's default is `python-httpx/<version>`, which bot
  protection answers with an HTML challenge page instead of the API: the
  failure that cost an afternoon on mcp-wordpress (RT #1596).

### Fixed

- **An oversized response says which request it answered.** It raised a bare
  `Response too large`, which named neither the URL nor the size, and this
  client is pointed at two different gateways by `base_url` — so the message
  could not even say which one. It now names the method, the full requested
  URL, the status, the content-type and the limit.

- **A non-JSON error body is quoted, not pasted.** That branch is what a WAF
  page or a gateway error takes, and it decoded the *whole* body into the
  exception message: a 20 MB error page became a 20 MB exception string, right
  at the limit the cap exists to enforce. It is now a bounded snippet that says
  where it came from.

- **One buffer for the bounded read.** It collected every chunk in a list and
  joined them, so near the ceiling both copies were live at once and the peak
  was roughly twice the limit. `bytearray` with `+=`, as mcp-wordpress already
  does.

### Changed

- Inherits constitution v1.36.0, whose MCP Server profile 1.8.0 states the
  outbound HTTP contract. This repo's `_read_capped` is the implementation the
  rest of RT #1601's sweep was ported from; these are the three things that
  were wrong with it.

### Security

- Upgraded locked dependencies within their declared ranges to clear the
  advisories the fleet dependency audit found (a stale lockfile).

## [0.2.1] - 2026-10-24

### Fixed

- `list_image_requests` / `get_image_request`: the `deep_link` now uses the
  public `REQ-NNNN` alias (`/image-requests?request=REQ-NNNN`) instead of the
  underlying Jira `HUM-NNNN` key. The `HUM-` form does not open reliably on
  images.redhat.com; the site resolves `REQ-` with the same number.

## [0.2.0] - 2026-10-23

### Added

- `list_image_requests` and `get_image_request`: two read-only tools over the
  Hummingbird image-request feed behind images.redhat.com/image-requests. Each
  request returns its HUM key, title, friendly status
  (Submitted/In progress/Delivered/Declined) and a public `deep_link`
  (`/image-requests?request=HUM-NNNN`) that opens it on the site.
- `RHHI_REQUESTS_API_URL` and `RHHI_SITE_URL` config, for the request API
  gateway (separate from the catalog API) and the deep-link site base.

### Changed

- Container base images pinned to `quay.io/hummingbird/python:3.14*` instead of
  `latest`, which moved to Python 3.15.0 on 2026-10-20 (crunchtools/constitution#66).

## [0.1.0] - 2026-10-16

### Added

- 12 read-only tools over the Hummingbird catalog API: images, tags, container
  details, SBOMs, per-tag and catalog-wide CVEs, CVE lookup, and release
  history by digest.
