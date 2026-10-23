"""Shared test fixtures for mcp-rhhi tests."""

from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

TEST_BASE = "https://api-hummingbird.hummingbird-project.io/v1"


@pytest.fixture(autouse=True)
def _reset_client_singleton() -> Generator[None, None, None]:
    """Reset the global client and config singletons between tests."""
    import mcp_rhhi_crunchtools.client as client_mod
    import mcp_rhhi_crunchtools.config as config_mod

    client_mod._client = None
    client_mod._requests_client = None
    config_mod._config = None
    yield
    client_mod._client = None
    client_mod._requests_client = None
    config_mod._config = None


def _mock_response(
    status_code: int = 200,
    json_data: Any = None,
    text: str = "",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Build a mock httpx.Response."""
    resp_headers = {"content-type": "application/json"}
    if headers:
        resp_headers.update(headers)
    return httpx.Response(
        status_code=status_code,
        headers=resp_headers,
        json=json_data if json_data is not None else None,
        text=text if json_data is None else None,
        request=httpx.Request("GET", "https://api-hummingbird.hummingbird-project.io/v1/test"),
    )


def _patch_client(mock_response: httpx.Response) -> Any:
    """Patch httpx.AsyncClient so every request returns mock_response."""
    import mcp_rhhi_crunchtools.client as client_mod
    import mcp_rhhi_crunchtools.config as config_mod

    client_mod._client = None
    client_mod._requests_client = None
    config_mod._config = None

    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_http.build_request = MagicMock(
        side_effect=lambda method, url, **_: httpx.Request(method, f"{TEST_BASE}{url}")
    )
    mock_http.send = AsyncMock(return_value=mock_response)

    return patch.object(httpx, "AsyncClient", return_value=mock_http)


def _sent_requests(client_cls: Any) -> list[httpx.Request]:
    """Every request the patched client sent."""
    return [call.args[0] for call in client_cls.return_value.send.await_args_list]


def _requested_url(client_cls: Any) -> str:
    """The path, below /v1, of the last request the patched client sent."""
    return _sent_requests(client_cls)[-1].url.raw_path.decode().removeprefix("/v1")
