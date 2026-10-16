"""Vulnerability tools: per-tag CVEs, catalog-wide stats, CVE lookup."""

from typing import Any

from ..client import get_client
from ..models import segment, severity_floor

DEFAULT_CVE_LIMIT = 50
MAX_DESCRIPTION_CHARS = 500


def _brief_cve(cve: dict[str, Any]) -> dict[str, Any]:
    description = cve.get("description") or ""
    if len(description) > MAX_DESCRIPTION_CHARS:
        description = description[:MAX_DESCRIPTION_CHARS] + "..."
    return {
        "id": cve.get("id"),
        "severity": cve.get("severity"),
        "fix_state": cve.get("fix_state"),
        "first_seen": cve.get("first_seen"),
        "url": cve.get("url"),
        "components": cve.get("components") or [],
        "description": description,
    }


def shape_scan(scan: dict[str, Any], min_severity: str | None, limit: int | None) -> dict[str, Any]:
    """Trim one tag's or release's scan to the CVEs at or above min_severity."""
    allowed = severity_floor(min_severity)
    vulns = [
        v
        for v in scan.get("vulnerabilities") or []
        if (v.get("severity") or "unknown").lower() in allowed
    ]
    cap = limit or DEFAULT_CVE_LIMIT
    return {
        "scanned_at": scan.get("scanned_at"),
        "scanner": scan.get("scanner"),
        "summary": scan.get("summary"),
        "matched": len(vulns),
        "truncated": len(vulns) > cap,
        "vulnerabilities": [_brief_cve(v) for v in vulns[:cap]],
    }


async def get_tag_vulnerabilities(
    name: str,
    canonical: str,
    min_severity: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """CVE scan for a canonical tag."""
    path = f"/images/{segment(name, 'name')}/vulnerabilities/{segment(canonical, 'canonical')}"
    scan: dict[str, Any] = await get_client().get(path)
    return {"image": name, "canonical": canonical, **shape_scan(scan, min_severity, limit)}


def _image_counts(tags: list[dict[str, Any]], cves: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Distinct CVEs per image by severity, joining `affected` indices to tags."""
    per_image: dict[str, dict[str, int]] = {}
    for cve in cves:
        severity = (cve.get("severity") or "unknown").lower()
        images = {tags[i].get("image") for i in cve.get("affected") or [] if 0 <= i < len(tags)}
        for image in images:
            counts = per_image.setdefault(str(image), {"total": 0})
            counts[severity] = counts.get(severity, 0) + 1
            counts["total"] += 1
    rows = [{"image": image, **counts} for image, counts in per_image.items()]
    return sorted(rows, key=lambda r: (-r.get("critical", 0), -r.get("high", 0), -r["total"]))


async def get_catalog_vulnerabilities(
    image: str | None = None,
    min_severity: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Catalog-wide CVE stats across all current tags, with per-image counts."""
    catalog = await get_client().get("/vulnerabilities")
    tags: list[dict[str, Any]] = catalog.get("tags") or []
    allowed = severity_floor(min_severity)
    cves = [
        c for c in catalog.get("cves") or [] if (c.get("severity") or "unknown").lower() in allowed
    ]
    if image:
        idxs = {i for i, t in enumerate(tags) if t.get("image") == image}
        cves = [c for c in cves if idxs.intersection(c.get("affected") or [])]

    per_image = _image_counts(tags, cves)
    if image:
        per_image = [r for r in per_image if r["image"] == image]
    cap = limit or DEFAULT_CVE_LIMIT
    return {
        "computed_at": catalog.get("computed_at"),
        "catalog_summary": catalog.get("summary"),
        "images": per_image,
        "matched": len(cves),
        "truncated": len(cves) > cap,
        "cves": [
            {k: c.get(k) for k in ("id", "severity", "first_seen", "url")} for c in cves[:cap]
        ],
    }


async def find_cve(cve_id: str) -> dict[str, Any]:
    """Which current catalog tags a CVE (or GHSA/GO advisory) affects."""
    catalog = await get_client().get("/vulnerabilities")
    tags: list[dict[str, Any]] = catalog.get("tags") or []
    wanted = cve_id.strip().upper()
    for cve in catalog.get("cves") or []:
        if (cve.get("id") or "").upper() == wanted:
            affected = [tags[i] for i in cve.get("affected") or [] if 0 <= i < len(tags)]
            return {
                "found": True,
                "computed_at": catalog.get("computed_at"),
                **_brief_cve(cve),
                "affected_images": sorted({str(t.get("image")) for t in affected}),
                "affected_tags": affected,
            }
    return {
        "found": False,
        "id": cve_id,
        "computed_at": catalog.get("computed_at"),
        "note": "Not present in any current (non-superseded) catalog tag.",
    }
