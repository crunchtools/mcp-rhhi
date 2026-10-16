"""FastMCP server setup for the Hummingbird catalog MCP.

This module creates and configures the MCP server with all tools.
"""

from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from .models import (
    Digest,
    HistoryLimit,
    ListLimit,
    OptionalQuery,
    OptionalSbomCategory,
    OptionalSeverity,
    OptionalSlug,
    ReadmeChars,
    Slug,
    VulnId,
)
from .tools import (
    find_cve,
    get_catalog_vulnerabilities,
    get_image,
    get_release_details,
    get_release_history,
    get_release_sbom,
    get_release_vulnerabilities,
    get_sbom,
    get_tag_details,
    get_tag_vulnerabilities,
    list_images,
    list_tags,
)

# A gateway drops an invalid optional argument only on a tool annotated read-only;
# on anything else it refuses the call. Only tools that change nothing get this.
READ_ONLY = {"readOnlyHint": True}

mcp = FastMCP(
    name="mcp-rhhi-crunchtools",
    version="0.1.0",
    instructions=(
        "Hummingbird / Red Hat Hardened Images catalog: minimal, distroless OCI "
        "images. Typical flow: list_images to find an image, list_tags for its "
        "current tags (pull_url, digest, canonical), then get_tag_details, "
        "get_sbom or get_tag_vulnerabilities with the canonical tag. Use the "
        "'builder' variant for build stages and 'default' for runtime. "
        "get_catalog_vulnerabilities and find_cve cover every current tag."
    ),
)

ImageName = Annotated[
    Slug, Field(description="Image name, e.g. 'python', 'nodejs', 'aspnet-runtime'")
]
Canonical = Annotated[
    Slug,
    Field(description="Canonical tag from list_tags, e.g. '3.14.8' or '3.14.8-builder'"),
]
ReleaseDigest = Annotated[
    Digest,
    Field(description="Manifest list digest (sha256:... or bare hex) from get_release_history"),
]
Arch = Annotated[
    OptionalSlug, Field(description="Architecture, e.g. 'amd64', 'arm64'; omit for all")
]
SbomArch = Annotated[
    OptionalSlug,
    Field(description="Architecture whose packages to list (default amd64); counts cover all"),
]
PackageQuery = Annotated[
    OptionalQuery, Field(description="Case-insensitive substring of the package name")
]
SbomCategory = Annotated[
    OptionalSbomCategory,
    Field(description="Only packages in this category: runtime, build, source"),
]
MinSeverity = Annotated[
    OptionalSeverity,
    Field(description="Only CVEs at or above: critical, high, medium, low"),
]
SbomLimit = Annotated[ListLimit, Field(description="Max packages returned (default 100)")]
CveLimit = Annotated[ListLimit, Field(description="Max CVEs returned (default 50)")]


@mcp.tool(annotations=READ_ONLY)
async def list_images_tool(
    query: Annotated[
        OptionalQuery, Field(description="Case-insensitive substring of name or summary")
    ] = None,
    category: Annotated[
        OptionalQuery,
        Field(description="Exact application_category, e.g. 'Programming Languages & Runtimes'"),
    ] = None,
) -> dict[str, Any]:
    """List images in the Hummingbird catalog with streams, variants and pull URL.

    The response also lists every category, for use as `category`.
    """
    return await list_images(query=query, category=category)


@mcp.tool(annotations=READ_ONLY)
async def get_image_tool(
    name: ImageName,
    include_readme: Annotated[
        bool, Field(description="Include the image README as plain text (usage, env vars)")
    ] = False,
    readme_max_chars: Annotated[
        ReadmeChars, Field(description="README length cap (default 20000)")
    ] = None,
) -> dict[str, Any]:
    """Get an image's metadata: summary, streams, variants, licenses, architectures."""
    return await get_image(
        name=name, include_readme=include_readme, readme_max_chars=readme_max_chars
    )


@mcp.tool(annotations=READ_ONLY)
async def list_tags_tool(
    name: ImageName,
    stream: Annotated[OptionalSlug, Field(description="Version stream, e.g. '3.14', '24'")] = None,
    variant: Annotated[
        OptionalSlug, Field(description="Variant, e.g. 'default', 'builder', 'fips'")
    ] = None,
    include_superseded: Annotated[
        bool, Field(description="Also return tags replaced by a newer one")
    ] = False,
) -> dict[str, Any]:
    """List an image's tags with pull_url, digest, canonical tag and sizes.

    Only current (non-superseded) tags unless include_superseded is set.
    """
    return await list_tags(
        name=name, stream=stream, variant=variant, include_superseded=include_superseded
    )


@mcp.tool(annotations=READ_ONLY)
async def get_tag_details_tool(
    name: ImageName,
    canonical: Canonical,
    arch: Arch = None,
) -> dict[str, Any]:
    """Get a tag's container config and provenance per architecture.

    User, entrypoint, cmd, env, exposed ports, working dir, labels, the
    Containerfile, source repo/commit, SLSA level and build system.
    """
    return await get_tag_details(name=name, canonical=canonical, arch=arch)


@mcp.tool(annotations=READ_ONLY)
async def get_sbom_tool(
    name: ImageName,
    canonical: Canonical,
    *,
    arch: SbomArch = None,
    package_query: PackageQuery = None,
    category: SbomCategory = None,
    limit: SbomLimit = None,
) -> dict[str, Any]:
    """Get a tag's SBOM: package counts per arch and a filterable package list."""
    return await get_sbom(
        name=name,
        canonical=canonical,
        arch=arch,
        package_query=package_query,
        category=category,
        limit=limit,
    )


@mcp.tool(annotations=READ_ONLY)
async def get_tag_vulnerabilities_tool(
    name: ImageName,
    canonical: Canonical,
    min_severity: MinSeverity = None,
    limit: CveLimit = None,
) -> dict[str, Any]:
    """Get the CVE scan for a tag: summary counts and each CVE with components."""
    return await get_tag_vulnerabilities(
        name=name, canonical=canonical, min_severity=min_severity, limit=limit
    )


@mcp.tool(annotations=READ_ONLY)
async def get_catalog_vulnerabilities_tool(
    image: Annotated[OptionalSlug, Field(description="Restrict to one image name")] = None,
    min_severity: MinSeverity = None,
    limit: CveLimit = None,
) -> dict[str, Any]:
    """Get catalog-wide CVE stats across every current tag, with per-image counts.

    catalog_summary is the unfiltered catalog total; images, matched and cves
    reflect the image and min_severity filters.
    """
    return await get_catalog_vulnerabilities(image=image, min_severity=min_severity, limit=limit)


@mcp.tool(annotations=READ_ONLY)
async def find_cve_tool(
    cve_id: Annotated[
        VulnId, Field(description="Advisory ID, CVE-YYYY-NNNN, GHSA-xxxx-xxxx-xxxx or GO-YYYY-NNNN")
    ],
) -> dict[str, Any]:
    """Find which current catalog images and tags a CVE affects."""
    return await find_cve(cve_id=cve_id)


@mcp.tool(annotations=READ_ONLY)
async def get_release_history_tool(
    name: ImageName,
    stream: Annotated[Slug, Field(description="Version stream, e.g. '3.14', '24', 'latest'")],
    variant: Annotated[Slug, Field(description="Variant, e.g. 'default', 'builder'")] = "default",
    limit: Annotated[HistoryLimit, Field(description="Max releases (default 20)")] = None,
) -> dict[str, Any]:
    """List past releases (digest, date, source commit) of a stream and variant."""
    return await get_release_history(name=name, stream=stream, variant=variant, limit=limit)


@mcp.tool(annotations=READ_ONLY)
async def get_release_details_tool(
    name: ImageName,
    digest: ReleaseDigest,
    arch: Arch = None,
) -> dict[str, Any]:
    """Get the container config and provenance of a historical release by digest."""
    return await get_release_details(name=name, digest=digest, arch=arch)


@mcp.tool(annotations=READ_ONLY)
async def get_release_sbom_tool(
    name: ImageName,
    digest: ReleaseDigest,
    *,
    arch: SbomArch = None,
    package_query: PackageQuery = None,
    category: SbomCategory = None,
    limit: SbomLimit = None,
) -> dict[str, Any]:
    """Get the SBOM of a historical release by digest."""
    return await get_release_sbom(
        name=name,
        digest=digest,
        arch=arch,
        package_query=package_query,
        category=category,
        limit=limit,
    )


@mcp.tool(annotations=READ_ONLY)
async def get_release_vulnerabilities_tool(
    name: ImageName,
    digest: ReleaseDigest,
    min_severity: MinSeverity = None,
    limit: CveLimit = None,
) -> dict[str, Any]:
    """Get the CVE scan of a historical release by digest."""
    return await get_release_vulnerabilities(
        name=name, digest=digest, min_severity=min_severity, limit=limit
    )
