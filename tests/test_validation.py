"""Input validation tests: schema types, path helpers and config."""

import pytest
from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as FastMCPValidationError
from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError

from mcp_rhhi_crunchtools.config import Config
from mcp_rhhi_crunchtools.errors import ConfigurationError, ValidationError
from mcp_rhhi_crunchtools.models import (
    Digest,
    HistoryLimit,
    OptionalQuery,
    OptionalRequestStatus,
    OptionalSbomCategory,
    OptionalSeverity,
    OptionalSlug,
    RequestIdentifier,
    Slug,
    VulnId,
    digest_segment,
    segment,
    severity_floor,
)
from mcp_rhhi_crunchtools.server import mcp
from tests.conftest import _mock_response, _patch_client

HEX = "b" * 64


class TestSlug:
    """Image, stream, variant, canonical and arch names."""

    @pytest.mark.parametrize("value", ["python", "3.14.8-builder", "aspnet-runtime", "latest"])
    def test_valid(self, value: str) -> None:
        assert TypeAdapter(Slug).validate_python(value) == value

    def test_strips_whitespace(self) -> None:
        assert TypeAdapter(Slug).validate_python("  python ") == "python"

    @pytest.mark.parametrize(
        "value", ["", "   ", "../etc", "a/b", "py thon", "-lead", "x" * 129, "a;rm", "%2e%2e"]
    )
    def test_rejected(self, value: str) -> None:
        with pytest.raises(PydanticValidationError):
            TypeAdapter(Slug).validate_python(value)


class TestOptionalNormalization:
    """Absent optionals normalize to None instead of being rejected."""

    @pytest.mark.parametrize("value", ["", "   ", None])
    def test_optional_slug_blank(self, value: str | None) -> None:
        assert TypeAdapter(OptionalSlug).validate_python(value) is None

    @pytest.mark.parametrize("value", ["", "   ", None])
    def test_optional_query_blank(self, value: str | None) -> None:
        assert TypeAdapter(OptionalQuery).validate_python(value) is None

    @pytest.mark.parametrize("value", ["", " ", None, 0, -5])
    def test_limit_out_of_domain(self, value: int | str | None) -> None:
        assert TypeAdapter(HistoryLimit).validate_python(value) is None

    def test_limit_above_max_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            TypeAdapter(HistoryLimit).validate_python(501)

    def test_severity_case_insensitive(self) -> None:
        assert TypeAdapter(OptionalSeverity).validate_python("High") == "high"
        assert TypeAdapter(OptionalSeverity).validate_python("") is None

    def test_severity_unknown_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            TypeAdapter(OptionalSeverity).validate_python("severe")

    def test_sbom_category(self) -> None:
        assert TypeAdapter(OptionalSbomCategory).validate_python("RUNTIME") == "runtime"
        with pytest.raises(PydanticValidationError):
            TypeAdapter(OptionalSbomCategory).validate_python("docs")

    def test_request_status(self) -> None:
        assert TypeAdapter(OptionalRequestStatus).validate_python("submitted") == "Submitted"
        assert TypeAdapter(OptionalRequestStatus).validate_python(" IN PROGRESS ") == "In progress"
        assert TypeAdapter(OptionalRequestStatus).validate_python("") is None
        with pytest.raises(PydanticValidationError):
            TypeAdapter(OptionalRequestStatus).validate_python("waiting")

    def test_request_identifier(self) -> None:
        assert TypeAdapter(RequestIdentifier).validate_python("  HUM-8787 ") == "HUM-8787"
        assert TypeAdapter(RequestIdentifier).validate_python("Redis 8") == "Redis 8"
        with pytest.raises(PydanticValidationError):
            TypeAdapter(RequestIdentifier).validate_python("")

    def test_optional_slug_still_validates_values(self) -> None:
        with pytest.raises(PydanticValidationError):
            TypeAdapter(OptionalSlug).validate_python("../x")


class TestDigestAndVulnId:
    """Digest and advisory ID formats."""

    @pytest.mark.parametrize("value", [f"sha256:{HEX}", HEX, f"SHA256:{HEX.upper()}"])
    def test_digest_valid(self, value: str) -> None:
        TypeAdapter(Digest).validate_python(value)
        assert digest_segment(value) == HEX

    @pytest.mark.parametrize("value", ["", "sha256:abc", f"md5:{HEX}", f"sha256:{HEX}/../x"])
    def test_digest_rejected(self, value: str) -> None:
        with pytest.raises(PydanticValidationError):
            TypeAdapter(Digest).validate_python(value)
        with pytest.raises(ValidationError):
            digest_segment(value)

    @pytest.mark.parametrize("value", ["CVE-2025-12781", "GHSA-abcd-efgh-ijkl", "GO-2025-3750"])
    def test_vuln_id_valid(self, value: str) -> None:
        assert TypeAdapter(VulnId).validate_python(value) == value

    @pytest.mark.parametrize("value", ["", "CVE", "CVE-2025-1/../x", "<script>"])
    def test_vuln_id_rejected(self, value: str) -> None:
        with pytest.raises(PydanticValidationError):
            TypeAdapter(VulnId).validate_python(value)


class TestPathHelpers:
    """Defense in depth when tool functions are called directly."""

    def test_segment_valid(self) -> None:
        assert segment("3.14.8-builder", "canonical") == "3.14.8-builder"

    @pytest.mark.parametrize("value", ["", "../etc", "a/b", "a?b=c", "x" * 200])
    def test_segment_rejected(self, value: str) -> None:
        with pytest.raises(ValidationError):
            segment(value, "name")

    def test_severity_floor(self) -> None:
        assert severity_floor("high") == {"critical", "high"}
        assert severity_floor(None) == severity_floor("unknown")
        with pytest.raises(ValidationError):
            severity_floor("bogus")


class TestToolArguments:
    """Arguments are checked by the registered tool before any request."""

    @pytest.mark.asyncio
    async def test_traversal_never_reaches_client(self) -> None:
        with _patch_client(_mock_response(json_data={})) as client_cls:
            with pytest.raises((PydanticValidationError, FastMCPValidationError, ToolError)):
                await mcp.call_tool("get_image_tool", {"name": "../../admin"})
            assert client_cls.return_value.send.await_count == 0

    @pytest.mark.asyncio
    async def test_extra_argument_rejected(self) -> None:
        with (
            _patch_client(_mock_response(json_data={})),
            pytest.raises((PydanticValidationError, FastMCPValidationError, ToolError)),
        ):
            await mcp.call_tool("list_images_tool", {"bogus": 1})

    @pytest.mark.asyncio
    async def test_blank_optionals_served(self) -> None:
        args = {"name": "python", "stream": "", "variant": None, "include_superseded": False}
        with _patch_client(_mock_response(json_data={"tags": []})):
            result = await mcp.call_tool("list_tags_tool", args)
        assert result.structured_content is not None
        assert result.structured_content["count"] == 0


class TestConfig:
    """Environment configuration."""

    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RHHI_API_URL", raising=False)
        monkeypatch.delenv("RHHI_REQUESTS_API_URL", raising=False)
        monkeypatch.delenv("RHHI_SITE_URL", raising=False)
        monkeypatch.delenv("RHHI_TIMEOUT", raising=False)
        config = Config()
        assert config.api_base_url == "https://api-hummingbird.hummingbird-project.io/v1"
        assert config.requests_api_base_url.startswith("https://")
        assert config.site_base_url == "https://images.redhat.com"
        assert config.timeout == 30.0

    def test_custom_request_urls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RHHI_API_URL", raising=False)
        monkeypatch.setenv("RHHI_REQUESTS_API_URL", "https://example.com/prod/")
        monkeypatch.setenv("RHHI_SITE_URL", "http://localhost:3000")
        config = Config()
        assert config.requests_api_base_url == "https://example.com/prod"
        assert config.site_base_url == "http://localhost:3000"

    def test_bad_request_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RHHI_API_URL", raising=False)
        monkeypatch.setenv("RHHI_REQUESTS_API_URL", "http://example.com")
        with pytest.raises(ConfigurationError):
            Config()

    def test_custom(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RHHI_API_URL", "http://localhost:9000/")
        monkeypatch.setenv("RHHI_TIMEOUT", "5")
        config = Config()
        assert config.api_base_url == "http://localhost:9000/v1"
        assert config.timeout == 5.0
        assert "localhost:9000" in repr(config)

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com",
            "not a url",
            "ftp://",
            "https://user:pw@example.com",
            "https://example.com/?token=x",
            "https://example.com:99999",
        ],
    )
    def test_bad_url(self, monkeypatch: pytest.MonkeyPatch, url: str) -> None:
        monkeypatch.setenv("RHHI_API_URL", url)
        with pytest.raises(ConfigurationError):
            Config()

    @pytest.mark.parametrize("timeout", ["abc", "0", "-1", "9999"])
    def test_bad_timeout(self, monkeypatch: pytest.MonkeyPatch, timeout: str) -> None:
        monkeypatch.delenv("RHHI_API_URL", raising=False)
        monkeypatch.setenv("RHHI_TIMEOUT", timeout)
        with pytest.raises(ConfigurationError):
            Config()
