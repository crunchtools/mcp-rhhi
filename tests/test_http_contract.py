"""The outbound HTTP contract (constitution v1.36.0, MCP Server profile Layer 3).

These drive a real `httpx.AsyncClient` over a `MockTransport`, rather than the
shared `_patch_client` helper that stands an AsyncMock in for the client. That
matters for exactly one of them: the agent string is a header the *client* adds,
so a mocked `send` never sees it go out.
"""

from collections.abc import AsyncIterator, Callable, Generator
from contextlib import contextmanager
from importlib.metadata import version
from typing import Any

import httpx
import pytest

from mcp_rhhi_crunchtools import client as client_mod
from mcp_rhhi_crunchtools.errors import CatalogApiError

Handler = Callable[[httpx.Request], httpx.Response]


async def _chunks(chunk: bytes, times: int) -> AsyncIterator[bytes]:
    """A chunked body, which carries no content-length -- what a header check misses."""
    for _ in range(times):
        yield chunk


@contextmanager
def _serving(handler: Handler) -> Generator[None, None, None]:
    """Run every client the process builds on a MockTransport."""
    real = httpx.AsyncClient

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("transport", None)
        return real(transport=httpx.MockTransport(handler), **kwargs)

    import mcp_rhhi_crunchtools.config as config_mod

    client_mod._client = None
    client_mod._requests_client = None
    config_mod._config = None
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(httpx, "AsyncClient", factory)
        yield


class TestUserAgent:
    """A request says what it is, and the version cannot drift from the release."""

    @pytest.mark.asyncio
    async def test_outgoing_request_names_the_product_and_version(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["User-Agent"])
            return httpx.Response(200, json={"images": []})

        with _serving(handler):
            await client_mod.get_client().get("/images")

        expected = (
            f"mcp-rhhi-crunchtools/{version('mcp-rhhi-crunchtools')} "
            "(+https://github.com/crunchtools/mcp-rhhi)"
        )
        assert seen == [expected]
        assert "python-httpx" not in seen[0]

    @pytest.mark.asyncio
    async def test_the_request_gateway_client_sends_it_too(self) -> None:
        """Two base URLs, one contract: the second client is built separately."""
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["User-Agent"])
            return httpx.Response(200, json={"requests": []})

        with _serving(handler):
            await client_mod.get_requests_client().get("/requests")

        assert len(seen) == 1
        assert "mcp-rhhi-crunchtools/" in seen[0]


class TestResponseCeiling:
    """The cap is enforced while reading, on the decoded body."""

    @pytest.mark.asyncio
    async def test_chunked_body_over_the_cap_names_the_request(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(client_mod, "MAX_RESPONSE_SIZE", 4096)

        def handler(_request: httpx.Request) -> httpx.Response:
            response = httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=_chunks(b"x" * 1024, 16),
            )
            assert "content-length" not in response.headers
            return response

        with _serving(handler), pytest.raises(CatalogApiError) as caught:
            await client_mod.get_client().get("/images")

        message = str(caught.value)
        assert "sent over the 4096 byte limit" in message
        assert "/v1/images" in message


class TestErrorNamesTheSite:
    """RT #1596: the message has to say which site answered, and with what."""

    @pytest.mark.asyncio
    async def test_a_challenge_page_is_quoted_and_bounded(self) -> None:
        """A non-JSON error body used to be decoded whole into the message."""
        huge = "<html><title>Attention Required!</title>" + "y" * 100_000

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, headers={"content-type": "text/html"}, text=huge)

        with _serving(handler), pytest.raises(CatalogApiError) as caught:
            await client_mod.get_client().get("/images")

        message = str(caught.value)
        assert "Attention Required!" in message
        assert "text/html" in message
        assert "/v1/images" in message
        # Bounded: the old code decoded the whole body into the exception.
        assert len(message) < 500


class TestSnippetBudget:
    """The manifest caps a quoted body at 200 characters, so it is 200."""

    def test_a_long_body_is_cut_to_the_cap_including_the_ellipsis(self) -> None:
        snippet = client_mod._body_snippet(b"y" * 100_000)

        assert len(snippet) == client_mod.BODY_SNIPPET_CHARS
        assert snippet.endswith("...")

    def test_a_short_body_is_quoted_whole(self) -> None:
        assert client_mod._body_snippet(b"nope") == "nope"

    def test_an_empty_body_says_so(self) -> None:
        assert client_mod._body_snippet(b"") == "<empty body>"


class TestJsonErrorBranch:
    """A server-chosen `error` field is as long as the server made it."""

    @pytest.mark.asyncio
    async def test_a_json_error_is_capped_and_names_the_request(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"error": "z" * 100_000})

        with _serving(handler), pytest.raises(CatalogApiError) as caught:
            await client_mod.get_client().get("/images")

        message = str(caught.value)
        assert "/v1/images" in message
        assert "application/json" in message
        assert len(message) < 500
