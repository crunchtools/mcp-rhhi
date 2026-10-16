"""Release history tools: immutable per-digest details, SBOMs and CVEs."""

from typing import Any

from ..client import get_client
from ..models import digest_segment, segment
from .tags import select_arches, shape_sbom
from .vulnerabilities import shape_scan

DEFAULT_HISTORY_LIMIT = 20


async def get_release_history(
    name: str,
    stream: str,
    variant: str = "default",
    limit: int | None = None,
) -> dict[str, Any]:
    """Releases (by digest) of one stream and variant, newest first."""
    path = (
        f"/images/{segment(name, 'name')}/history/"
        f"{segment(stream, 'stream')}/{segment(variant, 'variant')}"
    )
    history = await get_client().get(path)
    releases: list[dict[str, Any]] = history.get("releases") or []
    releases = sorted(releases, key=lambda r: r.get("oldest_created") or "", reverse=True)
    cap = limit or DEFAULT_HISTORY_LIMIT
    return {
        "image": name,
        "stream": stream,
        "variant": variant,
        "count": len(releases),
        "truncated": len(releases) > cap,
        "releases": releases[:cap],
    }


async def get_release_details(
    name: str,
    digest: str,
    arch: str | None = None,
) -> dict[str, Any]:
    """Container config and provenance of a historical release."""
    path = f"/images/{segment(name, 'name')}/releases/details/{digest_segment(digest)}"
    details: dict[str, Any] = await get_client().get(path)
    return {"image": name, "digest": digest, "architectures": select_arches(details, arch)}


async def get_release_sbom(
    name: str,
    digest: str,
    *,
    arch: str | None = None,
    package_query: str | None = None,
    category: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """SBOM of a historical release."""
    path = f"/images/{segment(name, 'name')}/releases/sbom/{digest_segment(digest)}"
    sbom: dict[str, Any] = await get_client().get(path)
    return {
        "image": name,
        "digest": digest,
        **shape_sbom(sbom, arch=arch, package_query=package_query, category=category, limit=limit),
    }


async def get_release_vulnerabilities(
    name: str,
    digest: str,
    min_severity: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """CVE scan of a historical release."""
    path = f"/images/{segment(name, 'name')}/releases/vulnerabilities/{digest_segment(digest)}"
    scan: dict[str, Any] = await get_client().get(path)
    return {"image": name, "digest": digest, **shape_scan(scan, min_severity, limit)}
