"""Hummingbird catalog API client with security hardening.

Every endpoint the catalog exposes is a GET, so the client only offers get().
"""

import json
import logging
from typing import Any

import httpx

from .config import get_config
from .errors import CatalogApiError, NotFoundError, RateLimitError

logger = logging.getLogger(__name__)

MAX_RESPONSE_SIZE = 20 * 1024 * 1024
MAX_RETRY_DIGITS = 6


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
                headers={"Accept": "application/json", "Accept-Encoding": "gzip"},
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
    """Read the decoded body, aborting as soon as it passes MAX_RESPONSE_SIZE."""
    content_length = response.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_RESPONSE_SIZE:
        raise CatalogApiError(0, "Response too large")
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > MAX_RESPONSE_SIZE:
            raise CatalogApiError(0, "Response too large")
        chunks.append(chunk)
    return b"".join(chunks)


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
        error_msg = body.decode("utf-8", errors="replace") or "Unknown error"
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
