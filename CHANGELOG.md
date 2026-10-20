# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Container base images pinned to `quay.io/hummingbird/python:3.14*` instead of
  `latest`, which moved to Python 3.15.0 on 2026-10-20 (crunchtools/constitution#66).

## [0.1.0] - 2026-10-16

### Added

- 12 read-only tools over the Hummingbird catalog API: images, tags, container
  details, SBOMs, per-tag and catalog-wide CVEs, CVE lookup, and release
  history by digest.
