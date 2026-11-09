"""Hummingbird catalog API client with security hardening.

Every endpoint the catalog exposes is a GET, so the client only offers get().
"""

import json
import logging
from importlib.metadata import version
from typing import Any

import httpx

from .config import get_config
from .errors import CatalogApiError, NotFoundError, RateLimitError

logger = logging.getLogger(__name__)

MAX_RESPONSE_SIZE = 20 * 1024 * 1024
MAX_RETRY_DIGITS = 6

# Identify this client by name. httpx otherwise sends `python-httpx/<version>`,
# which bot protection answers with an HTML challenge page instead of the API --
# the failure that cost an afternoon on mcp-wordpress (RT #1596). The version
# comes from installed package metadata so it cannot drift from pyproject.toml.
USER_AGENT = (
    f"mcp-rhhi-crunchtools/{version('mcp-rhhi-crunchtools')} "
    "(+https://github.com/crunchtools/mcp-rhhi)"
)

# How much of a body to quote back in an error. Enough to recognise a WAF page,
# a gateway error or an SSO redirect; short enough to stay readable, and bounded
# so a 20 MB error page does not become a 20 MB exception string.
BODY_SNIPPET_CHARS = 200


def _body_snippet(body: bytes) -> str:
    """A short, single-line excerpt of a response body, for an error message."""
    # Slice the bytes, then decode only that: decoding all of a megabyte body to
    # keep 200 characters copies it twice for nothing.
    prefix = body[: BODY_SNIPPET_CHARS * 4]
    collapsed = " ".join(prefix.decode("utf-8", errors="replace").split())
    if not collapsed:
        return "<empty body>"
    if len(collapsed) > BODY_SNIPPET_CHARS or len(body) > len(prefix):
        return collapsed[:BODY_SNIPPET_CHARS] + "..."
    return collapsed


def _where(response: httpx.Response) -> str:
    """Which request a response answered, for an error message.

    The requested URL rather than the path the caller passed: this client is
    pointed at two different gateways by `base_url`, so the path alone does not
    say which one answered, and a base URL that redirects returns a body from
    somewhere else entirely.
    """
    return (
        f"{response.request.method} {response.request.url} "
        f"(HTTP {response.status_code}, {response.headers.get('content-type', 'no content-type')})"
    )


class CatalogClient:
    """Async HTTP client for the catalog API v1.

    Security features:
    - HTTPS enforced by Config for non-localhost URLs
    - TLS certificate validation (httpx default)
    - Request timeout enforcement
    - Response size limit, enforced while the decoded body streams in
    """

    def __init__(self, base_url: str | None = None) -> None:
        self._config = get_config()
        self._base_url = base_url if base_url is not None else self._config.api_base_url
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "gzip",
                    "User-Agent": USER_AGENT,
                },
                timeout=httpx.Timeout(self._config.timeout),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get(self, path: str) -> Any:
        """GET a catalog path and return the decoded JSON.

        Args:
            path: API path below /v1, with every segment already URL-encoded

        Raises:
            CatalogApiError: On transport errors, oversized or non-JSON bodies
            NotFoundError: On 404
            RateLimitError: On 429
        """
        client = await self._get_client()
        logger.debug("API request: GET %s", path)
        request = client.build_request("GET", path)
        try:
            response = await client.send(request, stream=True)
            try:
                body = await _read_capped(response)
            finally:
                await response.aclose()
        except httpx.TimeoutException as e:
            raise CatalogApiError(0, f"Request timeout: {e}") from e
        except httpx.RequestError as e:
            raise CatalogApiError(0, f"Request failed: {e}") from e

        if not response.is_success:
            _raise_for_status(response, body, path)

        try:
            return json.loads(body)
        except ValueError as e:
            raise CatalogApiError(response.status_code, f"Invalid JSON response: {e}") from e


async def _read_capped(response: httpx.Response) -> bytes:
    """Read the decoded body, aborting as soon as it passes MAX_RESPONSE_SIZE.

    Decoded and not raw, which is the side of `Accept-Encoding: gzip` that
    matters: a limit counted on the wire is one a compressed body expands
    straight past after the count.
    """
    content_length = response.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_RESPONSE_SIZE:
        raise CatalogApiError(
            response.status_code,
            f"{_where(response)} declared {content_length} bytes, over the "
            f"{MAX_RESPONSE_SIZE} byte limit",
        )
    # One growing buffer rather than a list of chunks plus a `b"".join()`: near
    # the ceiling the join holds both copies at the same instant, so the peak is
    # roughly twice the limit this cap exists to bound. And the length is
    # checked BEFORE the chunk is copied in, because `aiter_bytes()` yields
    # whatever the stream produces -- a single chunk can be the whole body --
    # so appending first would let exactly the response this refuses into
    # memory on the way to refusing it.
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > MAX_RESPONSE_SIZE:
            raise CatalogApiError(
                response.status_code,
                f"{_where(response)} sent over the {MAX_RESPONSE_SIZE} byte limit",
            )
        body += chunk
    return bytes(body)


def _raise_for_status(response: httpx.Response, body: bytes, path: str) -> None:
    status_code = response.status_code
    if status_code == 404:
        raise NotFoundError(path)
    if status_code == 429:
        retry_after = response.headers.get("retry-after")
        valid = retry_after and retry_after.isdigit() and len(retry_after) <= MAX_RETRY_DIGITS
        seconds = int(retry_after) if valid else None
        raise RateLimitError(seconds)

    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        error_msg = str(parsed.get("error") or parsed.get("message") or parsed)
    else:
        # Not the whole body: this branch is what a WAF page or a gateway error
        # takes, and decoding a 20 MB one of those made a 20 MB exception
        # string. The snippet is bounded and says where it came from.
        error_msg = f"{_where(response)} returned {_body_snippet(body)}"
    raise CatalogApiError(status_code, error_msg)


_client: CatalogClient | None = None
_requests_client: CatalogClient | None = None


def get_client() -> CatalogClient:
    """Get the global catalog client instance."""
    global _client
    if _client is None:
        _client = CatalogClient()
    return _client


def get_requests_client() -> CatalogClient:
    """Get the global image-request client (points at the request API gateway)."""
    global _requests_client
    if _requests_client is None:
        _requests_client = CatalogClient(base_url=get_config().requests_api_base_url)
    return _requests_client
