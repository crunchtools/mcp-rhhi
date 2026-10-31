# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
