"""MCP RHHI CrunchTools - Secure MCP server for the Hummingbird image catalog.

Read-only access to the Hummingbird / Red Hat Hardened Images catalog API:
images, tags, container config, SBOMs, CVE scans and release history.

Usage:
    mcp-rhhi-crunchtools

    python -m mcp_rhhi_crunchtools

    uvx mcp-rhhi-crunchtools

Environment Variables:
    RHHI_API_URL: Optional. Catalog API base URL
        (default: https://api-hummingbird.hummingbird-project.io).
    RHHI_REQUESTS_API_URL: Optional. Image-request API gateway base URL
        (default: the gateway images.redhat.com/image-requests calls).
    RHHI_SITE_URL: Optional. Public site base URL for image-request deep links
        (default: https://images.redhat.com).
    RHHI_TIMEOUT: Optional. Request timeout in seconds (default: 30).

Example with Claude Code:
    claude mcp add mcp-rhhi-crunchtools -- uvx mcp-rhhi-crunchtools
"""

import argparse

from .server import mcp

__version__ = "0.2.0"
DEFAULT_PORT = 8030
__all__ = ["main", "mcp"]


def main() -> None:
    """Main entry point for the MCP server."""
    parser = argparse.ArgumentParser(description="MCP server for the Hummingbird image catalog")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to for HTTP transports (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Port to bind to for HTTP transports (default: 8030)",
    )
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport=args.transport, host=args.host, port=args.port)
