"""Tests for MCP tools.

These tests verify tool behavior without making actual API calls.
"""

import sys
from unittest.mock import MagicMock

import httpx
import pytest

import mcp_rhhi_crunchtools as pkg
from mcp_rhhi_crunchtools.errors import CatalogApiError, NotFoundError, RateLimitError
from mcp_rhhi_crunchtools.server import mcp
from mcp_rhhi_crunchtools.tools import (
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
from tests.conftest import _mock_response, _patch_client, _requested_url, _sent_requests

DIGEST = "sha256:" + "a" * 64

IMAGES = {
    "images": [
        {
            "name": "python",
            "summary": "Interpreted language",
            "application_category": "Programming Languages & Runtimes",
            "streams": ["3.14", "3.13"],
            "variants": [{"name": "default"}, {"name": "builder"}],
            "architectures": ["amd64", "arm64"],
            "latest_tag": "3.14.8",
            "pull_url": "registry.access.redhat.com/hi/python:latest",
        },
        {
            "name": "nginx",
            "summary": "Web server",
            "application_category": "Web Services",
            "streams": ["1.28"],
            "variants": [{"name": "default"}],
        },
    ]
}

TAGS = {
    "variants": [{"name": "default"}, {"name": "builder"}],
    "tags": [
        {
            "name": "3.14.8",
            "canonical": "3.14.8",
            "stream": "3.14",
            "variant": "default",
            "superseded": False,
            "digest": DIGEST,
        },
        {
            "name": "3.14.8-builder",
            "canonical": "3.14.8-builder",
            "stream": "3.14",
            "variant": "builder",
            "superseded": False,
        },
        {
            "name": "3.14.7",
            "canonical": "3.14.7",
            "stream": "3.14",
            "variant": "default",
            "superseded": True,
        },
        {
            "name": "3.13.9",
            "canonical": "3.13.9",
            "stream": "3.13",
            "variant": "default",
            "superseded": False,
        },
    ],
}

DETAILS = {
    "amd64": {"user": "65532", "cmd": ["python3"], "slsa_level": "SLSA Build L3"},
    "arm64": {"user": "65532", "cmd": ["python3"], "slsa_level": "SLSA Build L3"},
}

SBOM = {
    "amd64": {
        "runtime_count": 2,
        "build_count": 1,
        "source_count": 0,
        "packages": [
            {"name": "openssl-libs", "evr": "3.5.0-1", "type": "rpm", "category": "runtime"},
            {"name": "python3", "evr": "3.14.8-1", "type": "rpm", "category": "runtime"},
            {"name": "bash", "evr": "5.3-1", "type": "rpm", "category": "build"},
        ],
    },
    "arm64": {"runtime_count": 2, "build_count": 1, "source_count": 0, "packages": []},
}

SCAN = {
    "scanned_at": "2026-10-16T07:50:30Z",
    "scanner": "grype 0.119.0",
    "summary": {"total": 3, "critical": 1, "high": 1, "medium": 1},
    "vulnerabilities": [
        {
            "id": "CVE-2026-0001",
            "severity": "Critical",
            "description": "x" * 900,
            "components": [{"name": "openssl-libs@3.5.0-1"}],
        },
        {"id": "CVE-2026-0002", "severity": "High", "description": "high"},
        {"id": "CVE-2026-0003", "severity": "Medium", "description": "medium"},
    ],
}

CATALOG = {
    "computed_at": "2026-10-16T07:53:49Z",
    "summary": {"total": 3, "critical": 1, "high": 1, "medium": 1},
    "tags": [
        {"image": "python", "stream": "3.14", "variant": "default", "canonical": "3.14.8"},
        {"image": "python", "stream": "3.14", "variant": "builder", "canonical": "3.14.8-builder"},
        {"image": "nginx", "stream": "1.28", "variant": "default", "canonical": "1.28.0"},
    ],
    "cves": [
        {"id": "CVE-2026-0001", "severity": "Critical", "affected": [0, 1, 2]},
        {"id": "GHSA-abcd-efgh-ijkl", "severity": "High", "affected": [2]},
        {"id": "CVE-2026-0003", "severity": "Medium", "affected": [0, 99]},
    ],
}

HISTORY = {
    "releases": [
        {"digest": "sha256:" + "1" * 64, "oldest_created": "2026-10-01T00:00:00Z"},
        {"digest": "sha256:" + "2" * 64, "oldest_created": "2026-10-14T00:00:00Z"},
        {"digest": "sha256:" + "3" * 64, "oldest_created": "2026-10-07T00:00:00Z"},
    ]
}


class TestToolRegistration:
    """Tests to verify all tools are properly registered."""

    def test_imports(self) -> None:
        """All tool functions should be importable."""
        import mcp_rhhi_crunchtools.tools as tools_mod
        from mcp_rhhi_crunchtools.tools import __all__

        for name in __all__:
            assert callable(getattr(tools_mod, name)), f"{name} is not callable"

    def test_tool_count(self) -> None:
        """Server should have exactly 12 tools."""
        from mcp_rhhi_crunchtools.tools import __all__

        assert len(__all__) == 12

    @pytest.mark.asyncio
    async def test_registered_count(self) -> None:
        """Every tool function has a registered wrapper."""
        assert len(await mcp.list_tools()) == 12


READ_ONLY = frozenset(
    {
        "find_cve_tool",
        "get_catalog_vulnerabilities_tool",
        "get_image_tool",
        "get_release_details_tool",
        "get_release_history_tool",
        "get_release_sbom_tool",
        "get_release_vulnerabilities_tool",
        "get_sbom_tool",
        "get_tag_details_tool",
        "get_tag_vulnerabilities_tool",
        "list_images_tool",
        "list_tags_tool",
    }
)
WRITES: frozenset[str] = frozenset()

_IMAGE = {"name": "python"}
_TAG = {"name": "python", "canonical": "3.14.8"}
_RELEASE = {"name": "python", "digest": DIGEST}

READ_ONLY_CALLS: dict[str, dict[str, object]] = {
    "find_cve_tool": {"cve_id": "CVE-2026-0001"},
    "get_catalog_vulnerabilities_tool": {},
    "get_image_tool": _IMAGE,
    "get_release_details_tool": _RELEASE,
    "get_release_history_tool": {**_IMAGE, "stream": "3.14"},
    "get_release_sbom_tool": _RELEASE,
    "get_release_vulnerabilities_tool": _RELEASE,
    "get_sbom_tool": _TAG,
    "get_tag_details_tool": _TAG,
    "get_tag_vulnerabilities_tool": _TAG,
    "list_images_tool": {},
    "list_tags_tool": _IMAGE,
}


class TestReadOnlyAnnotation:
    """Every registered tool is classified, and the reads really only read."""

    @pytest.mark.asyncio
    async def test_every_tool_is_classified(self) -> None:
        """Each registered tool is in exactly one set; the hint matches READ_ONLY."""
        tools = await mcp.list_tools()
        assert READ_ONLY.isdisjoint(WRITES)
        assert {tool.name for tool in tools} == READ_ONLY | WRITES
        annotated = {
            tool.name
            for tool in tools
            if tool.annotations is not None
            and tool.annotations.model_dump(by_alias=True).get("readOnlyHint") is True
        }
        assert annotated == READ_ONLY

    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", sorted(READ_ONLY))
    async def test_read_only_tool_only_sends_get(self, name: str) -> None:
        """A read-only tool reaches the catalog with GET and no request body."""
        with _patch_client(_mock_response(json_data={})) as client_cls:
            await mcp.call_tool(name, READ_ONLY_CALLS[name])
        sent = _sent_requests(client_cls)
        assert sent
        for request in sent:
            assert request.method in {"GET", "HEAD"}
            assert request.content == b""


class TestRegisteredSchema:
    """The published inputSchema carries each parameter's valid domain."""

    @pytest.mark.asyncio
    async def test_optional_constraints_inside_any_of(self) -> None:
        """Optional constraints sit on the string/integer branch, not beside anyOf."""
        params = (await mcp.get_tool("get_sbom_tool")).parameters["properties"]
        assert params["name"]["pattern"]
        arch_branch = params["arch"]["anyOf"][0]
        assert arch_branch["pattern"]
        assert arch_branch["maxLength"] == 128
        assert params["limit"]["anyOf"][0] == {"type": "integer", "minimum": 1, "maximum": 1000}
        assert params["category"]["anyOf"][0]["enum"] == ["runtime", "build", "source"]

    @pytest.mark.asyncio
    async def test_no_free_form_objects(self) -> None:
        """Schemas are closed and no parameter is a bare object."""
        for tool in await mcp.list_tools():
            assert tool.parameters.get("additionalProperties") is False
            for prop in tool.parameters["properties"].values():
                assert prop.get("type") != "object"
                assert prop.get("description"), f"{tool.name} has an undocumented parameter"


class TestImageTools:
    """list_images and get_image."""

    @pytest.mark.asyncio
    async def test_list_images(self) -> None:
        with _patch_client(_mock_response(json_data=IMAGES)) as client_cls:
            result = await list_images()
        assert _requested_url(client_cls) == "/images"
        assert result["count"] == 2
        assert result["categories"] == ["Programming Languages & Runtimes", "Web Services"]
        assert result["images"][0]["variants"] == ["default", "builder"]

    @pytest.mark.asyncio
    async def test_list_images_filters(self) -> None:
        with _patch_client(_mock_response(json_data=IMAGES)):
            by_query = await list_images(query="WEB")
            by_category = await list_images(category="programming languages & runtimes")
        assert [i["name"] for i in by_query["images"]] == ["nginx"]
        assert [i["name"] for i in by_category["images"]] == ["python"]

    @pytest.mark.asyncio
    async def test_get_image_drops_readme_by_default(self) -> None:
        body = {"name": "python", "readme_html": "<h1>Python</h1><p>Use it.</p>"}
        with _patch_client(_mock_response(json_data=body)) as client_cls:
            result = await get_image("python")
        assert _requested_url(client_cls) == "/images/python"
        assert "readme_html" not in result
        assert "readme" not in result

    @pytest.mark.asyncio
    async def test_get_image_readme_text(self) -> None:
        body = {"name": "python", "readme_html": "<h1>Python</h1><p>Use &amp; enjoy.</p>"}
        with _patch_client(_mock_response(json_data=body)):
            result = await get_image("python", include_readme=True, readme_max_chars=8)
        assert result["readme"] == "Python\n\n"
        assert result["readme_truncated"] is True

    @pytest.mark.asyncio
    async def test_get_image_readme_unescaped(self) -> None:
        body = {"name": "python", "readme_html": "<p>Use &amp; enjoy.</p>"}
        with _patch_client(_mock_response(json_data=body)):
            result = await get_image("python", include_readme=True)
        assert result["readme"] == "Use & enjoy."
        assert result["readme_truncated"] is False


class TestTagTools:
    """list_tags, get_tag_details and get_sbom."""

    @pytest.mark.asyncio
    async def test_list_tags_current_only(self) -> None:
        with _patch_client(_mock_response(json_data=TAGS)) as client_cls:
            result = await list_tags("python")
        assert _requested_url(client_cls) == "/images/python/tags"
        assert result["count"] == 3
        assert all(not t["superseded"] for t in result["tags"])

    @pytest.mark.asyncio
    async def test_list_tags_filters(self) -> None:
        with _patch_client(_mock_response(json_data=TAGS)):
            result = await list_tags(
                "python", stream="3.14", variant="default", include_superseded=True
            )
        assert [t["canonical"] for t in result["tags"]] == ["3.14.8", "3.14.7"]

    @pytest.mark.asyncio
    async def test_get_tag_details(self) -> None:
        with _patch_client(_mock_response(json_data=DETAILS)) as client_cls:
            result = await get_tag_details("python", "3.14.8", arch="arm64")
        assert _requested_url(client_cls) == "/images/python/details/3.14.8"
        assert list(result["architectures"]) == ["arm64"]

    @pytest.mark.asyncio
    async def test_get_tag_details_unknown_arch(self) -> None:
        from mcp_rhhi_crunchtools.errors import ValidationError

        with _patch_client(_mock_response(json_data=DETAILS)), pytest.raises(ValidationError):
            await get_tag_details("python", "3.14.8", arch="mips")

    @pytest.mark.asyncio
    async def test_get_sbom_defaults_to_amd64(self) -> None:
        with _patch_client(_mock_response(json_data=SBOM)) as client_cls:
            result = await get_sbom("python", "3.14.8")
        assert _requested_url(client_cls) == "/images/python/sbom/3.14.8"
        assert result["packages_arch"] == "amd64"
        assert set(result["counts"]) == {"amd64", "arm64"}
        assert result["matched"] == 3

    @pytest.mark.asyncio
    async def test_get_sbom_filters_and_limit(self) -> None:
        with _patch_client(_mock_response(json_data=SBOM)):
            by_name = await get_sbom("python", "3.14.8", package_query="SSL")
            by_category = await get_sbom("python", "3.14.8", category="runtime", limit=1)
        assert [p["name"] for p in by_name["packages"]] == ["openssl-libs"]
        assert by_category["matched"] == 2
        assert by_category["truncated"] is True
        assert len(by_category["packages"]) == 1


class TestVulnerabilityTools:
    """Per-tag scans, catalog stats and CVE lookup."""

    @pytest.mark.asyncio
    async def test_get_tag_vulnerabilities(self) -> None:
        with _patch_client(_mock_response(json_data=SCAN)) as client_cls:
            result = await get_tag_vulnerabilities("python", "3.14.8", min_severity="high")
        assert _requested_url(client_cls) == "/images/python/vulnerabilities/3.14.8"
        assert [v["id"] for v in result["vulnerabilities"]] == ["CVE-2026-0001", "CVE-2026-0002"]
        assert result["vulnerabilities"][0]["description"].endswith("...")
        assert len(result["vulnerabilities"][0]["description"]) == 503

    @pytest.mark.asyncio
    async def test_get_catalog_vulnerabilities(self) -> None:
        with _patch_client(_mock_response(json_data=CATALOG)) as client_cls:
            result = await get_catalog_vulnerabilities()
        assert _requested_url(client_cls) == "/vulnerabilities"
        assert result["matched"] == 3
        assert result["catalog_summary"] == CATALOG["summary"]
        rows = {r["image"]: r for r in result["images"]}
        assert rows["python"] == {"image": "python", "total": 2, "critical": 1, "medium": 1}
        assert rows["nginx"] == {"image": "nginx", "total": 2, "critical": 1, "high": 1}

    @pytest.mark.asyncio
    async def test_get_catalog_vulnerabilities_for_image(self) -> None:
        with _patch_client(_mock_response(json_data=CATALOG)):
            result = await get_catalog_vulnerabilities(image="nginx", min_severity="high", limit=1)
        assert [r["image"] for r in result["images"]] == ["nginx"]
        assert result["matched"] == 2
        assert result["truncated"] is True

    @pytest.mark.asyncio
    async def test_find_cve(self) -> None:
        with _patch_client(_mock_response(json_data=CATALOG)):
            result = await find_cve("cve-2026-0003")
        assert result["found"] is True
        assert result["affected_images"] == ["python"]
        assert result["affected_tags"] == [CATALOG["tags"][0]]

    @pytest.mark.asyncio
    async def test_find_cve_missing(self) -> None:
        with _patch_client(_mock_response(json_data=CATALOG)):
            result = await find_cve("CVE-1999-0001")
        assert result["found"] is False


class TestReleaseTools:
    """History and immutable per-digest endpoints."""

    @pytest.mark.asyncio
    async def test_get_release_history_newest_first(self) -> None:
        with _patch_client(_mock_response(json_data=HISTORY)) as client_cls:
            result = await get_release_history("python", "3.14", limit=2)
        assert _requested_url(client_cls) == "/images/python/history/3.14/default"
        assert [r["oldest_created"][:10] for r in result["releases"]] == [
            "2026-10-14",
            "2026-10-07",
        ]
        assert result["truncated"] is True

    @pytest.mark.asyncio
    async def test_get_release_details_strips_prefix(self) -> None:
        with _patch_client(_mock_response(json_data=DETAILS)) as client_cls:
            result = await get_release_details("python", DIGEST)
        assert _requested_url(client_cls) == "/images/python/releases/details/" + "a" * 64
        assert set(result["architectures"]) == {"amd64", "arm64"}

    @pytest.mark.asyncio
    async def test_get_release_sbom(self) -> None:
        with _patch_client(_mock_response(json_data=SBOM)) as client_cls:
            result = await get_release_sbom("python", "A" * 64, arch="arm64")
        assert _requested_url(client_cls) == "/images/python/releases/sbom/" + "a" * 64
        assert result["packages_arch"] == "arm64"

    @pytest.mark.asyncio
    async def test_get_release_vulnerabilities(self) -> None:
        with _patch_client(_mock_response(json_data=SCAN)) as client_cls:
            result = await get_release_vulnerabilities("python", DIGEST)
        assert _requested_url(client_cls).startswith("/images/python/releases/vulnerabilities/")
        assert result["matched"] == 3


class TestClientErrorHandling:
    """Status codes and transport failures become safe UserErrors."""

    @pytest.mark.asyncio
    async def test_404(self) -> None:
        with (
            _patch_client(_mock_response(404, json_data={"error": "not_found"})),
            pytest.raises(NotFoundError),
        ):
            await get_image("missing")

    @pytest.mark.asyncio
    async def test_429_retry_after(self) -> None:
        resp = _mock_response(429, json_data={}, headers={"retry-after": "7"})
        with _patch_client(resp), pytest.raises(RateLimitError, match="7 seconds"):
            await list_images()

    @pytest.mark.asyncio
    async def test_500_message_truncated(self) -> None:
        with (
            _patch_client(_mock_response(500, json_data={"error": "e" * 1000})),
            pytest.raises(CatalogApiError) as exc,
        ):
            await list_images()
        assert len(str(exc.value)) <= 200

    @pytest.mark.asyncio
    async def test_invalid_json(self) -> None:
        resp = _mock_response(200, text="<html>", headers={"content-type": "text/html"})
        with _patch_client(resp), pytest.raises(CatalogApiError, match="Invalid JSON"):
            await list_images()

    @pytest.mark.asyncio
    async def test_oversized_response(self) -> None:
        resp = _mock_response(200, json_data={}, headers={"content-length": str(50 * 1024**2)})
        with _patch_client(resp), pytest.raises(CatalogApiError, match="too large"):
            await list_images()

    @pytest.mark.asyncio
    async def test_transport_error(self) -> None:
        with _patch_client(_mock_response(json_data={})) as client_cls:
            client_cls.return_value.send.side_effect = httpx.ConnectError("boom")
            with pytest.raises(CatalogApiError, match="Request failed"):
                await list_images()

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        with _patch_client(_mock_response(json_data={})) as client_cls:
            client_cls.return_value.send.side_effect = httpx.ReadTimeout("slow")
            with pytest.raises(CatalogApiError, match="timeout"):
                await list_images()

    @pytest.mark.asyncio
    async def test_oversized_body_without_content_length(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import mcp_rhhi_crunchtools.client as client_mod

        monkeypatch.setattr(client_mod, "MAX_RESPONSE_SIZE", 10)
        resp = _mock_response(200, text='{"images": ["' + "x" * 50 + '"]}')
        resp.headers.pop("content-length", None)
        with _patch_client(resp), pytest.raises(CatalogApiError, match="too large"):
            await list_images()

    @pytest.mark.asyncio
    async def test_absurd_retry_after_ignored(self) -> None:
        resp = _mock_response(429, json_data={}, headers={"retry-after": "9" * 50})
        with _patch_client(resp), pytest.raises(RateLimitError) as exc:
            await list_images()
        assert str(exc.value) == "Rate limit exceeded."


class TestErrorSafety:
    """Errors do not echo unbounded identifiers."""

    def test_not_found_truncates_identifier(self) -> None:
        error = NotFoundError("x" * 200)
        assert "x" * 41 not in str(error)
        assert str(error).endswith("...")


class TestEntryPoint:
    """main() hands each transport to mcp.run."""

    @pytest.mark.parametrize(
        ("argv", "expected"),
        [
            ([], {}),
            (["--transport", "stdio"], {}),
            (
                ["--transport", "sse", "--port", "9001"],
                {"transport": "sse", "host": "127.0.0.1", "port": 9001},
            ),
            (
                ["--transport", "streamable-http", "--host", "10.0.0.5"],
                {"transport": "streamable-http", "host": "10.0.0.5", "port": 8030},
            ),
        ],
    )
    def test_main(
        self, monkeypatch: pytest.MonkeyPatch, argv: list[str], expected: dict[str, object]
    ) -> None:
        run = MagicMock()
        monkeypatch.setattr(pkg.mcp, "run", run)
        monkeypatch.setattr(sys, "argv", ["mcp-rhhi-crunchtools", *argv])
        pkg.main()
        run.assert_called_once_with(**expected)
