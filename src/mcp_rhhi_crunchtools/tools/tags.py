"""Tag tools: find tags, read container config, read SBOMs."""

from typing import Any

from ..client import get_client
from ..errors import ValidationError
from ..models import segment

DEFAULT_SBOM_LIMIT = 100
PREFERRED_ARCH = "amd64"


def _summarize_tag(tag: dict[str, Any]) -> dict[str, Any]:
    return {
        key: tag.get(key)
        for key in (
            "name",
            "canonical",
            "stream",
            "variant",
            "superseded",
            "deprecated",
            "pull_url",
            "digest",
            "architectures",
            "sizes",
            "oldest_created",
        )
    }


def select_arches(per_arch: dict[str, Any], arch: str | None) -> dict[str, Any]:
    """Narrow an arch-keyed response to one arch, or pass it through."""
    if arch is None:
        return per_arch
    if arch not in per_arch:
        raise ValidationError(f"arch must be one of: {', '.join(sorted(per_arch))}")
    return {arch: per_arch[arch]}


def shape_sbom(
    per_arch: dict[str, Any],
    *,
    arch: str | None,
    package_query: str | None,
    category: str | None,
    limit: int | None,
) -> dict[str, Any]:
    """Package counts for every arch, plus a filtered package list for one arch."""
    counts = {
        a: {k: v.get(k) for k in ("runtime_count", "build_count", "source_count")}
        for a, v in per_arch.items()
    }
    if not per_arch:
        return {"counts": counts, "packages": [], "matched": 0}

    if arch is None:
        arch = PREFERRED_ARCH if PREFERRED_ARCH in per_arch else sorted(per_arch)[0]
    packages: list[dict[str, Any]] = select_arches(per_arch, arch)[arch].get("packages") or []

    if category:
        packages = [p for p in packages if p.get("category") == category]
    if package_query:
        needle = package_query.lower()
        packages = [p for p in packages if needle in (p.get("name") or "").lower()]

    cap = limit or DEFAULT_SBOM_LIMIT
    return {
        "counts": counts,
        "packages_arch": arch,
        "matched": len(packages),
        "truncated": len(packages) > cap,
        "packages": [
            {k: p.get(k) for k in ("name", "evr", "type", "category", "license", "purl")}
            for p in packages[:cap]
        ],
    }


async def list_tags(
    name: str,
    stream: str | None = None,
    variant: str | None = None,
    include_superseded: bool = False,
) -> dict[str, Any]:
    """List an image's tags; current (non-superseded) ones only by default."""
    listing = await get_client().get(f"/images/{segment(name, 'name')}/tags")
    tags: list[dict[str, Any]] = listing.get("tags") or []
    if not include_superseded:
        tags = [t for t in tags if not t.get("superseded")]
    if stream:
        tags = [t for t in tags if t.get("stream") == stream]
    if variant:
        tags = [t for t in tags if t.get("variant") == variant]
    return {
        "image": name,
        "count": len(tags),
        "variants": listing.get("variants"),
        "tags": [_summarize_tag(t) for t in tags],
    }


async def get_tag_details(
    name: str,
    canonical: str,
    arch: str | None = None,
) -> dict[str, Any]:
    """Container config and provenance for a canonical tag, per architecture."""
    path = f"/images/{segment(name, 'name')}/details/{segment(canonical, 'canonical')}"
    details: dict[str, Any] = await get_client().get(path)
    return {"image": name, "canonical": canonical, "architectures": select_arches(details, arch)}


async def get_sbom(
    name: str,
    canonical: str,
    *,
    arch: str | None = None,
    package_query: str | None = None,
    category: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """SBOM for a canonical tag: counts per arch and a filtered package list."""
    path = f"/images/{segment(name, 'name')}/sbom/{segment(canonical, 'canonical')}"
    sbom: dict[str, Any] = await get_client().get(path)
    return {
        "image": name,
        "canonical": canonical,
        **shape_sbom(sbom, arch=arch, package_query=package_query, category=category, limit=limit),
    }
