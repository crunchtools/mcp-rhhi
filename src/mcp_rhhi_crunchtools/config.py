"""Configuration handling.

The Hummingbird catalog API is public and needs no credentials, so the only
settings are where it lives and how long to wait for it.
"""

import logging
import os
from urllib.parse import urlparse

from .errors import ConfigurationError

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "https://api-hummingbird.hummingbird-project.io"
# Image requests are served by a separate API gateway from the catalog: they are
# sourced from Jira HUM "Image Request" stories and published on
# images.redhat.com/image-requests. This is the gateway the public site itself calls.
DEFAULT_REQUESTS_API_URL = "https://s4jv1nv2e0.execute-api.us-east-1.amazonaws.com/prod"
DEFAULT_SITE_URL = "https://images.redhat.com"
DEFAULT_TIMEOUT = 30.0
MAX_TIMEOUT = 300.0
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def _clean_url(raw: str, name: str) -> str:
    """Validate and normalize an API/site URL the same way for every setting."""
    url = raw.strip().rstrip("/")
    parsed = urlparse(url)
    try:
        _ = parsed.port
    except ValueError as e:
        raise ConfigurationError(f"Invalid {name}: bad port") from e
    if not parsed.scheme or not parsed.netloc:
        raise ConfigurationError(f"Invalid {name}: must be a URL like {DEFAULT_API_URL}")
    if parsed.scheme != "https" and parsed.hostname not in LOCAL_HOSTS:
        raise ConfigurationError(f"{name} must use HTTPS for non-localhost URLs")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigurationError(f"{name} must not carry credentials, a query string or a fragment")
    return url


class Config:
    """API locations and request timeout, read from the environment.

    Covers the catalog API, the separate image-request API gateway, the public
    site URL used to build image-request deep links, and the request timeout.
    """

    def __init__(self) -> None:
        """Initialize configuration from environment variables.

        Raises:
            ConfigurationError: If an environment variable is invalid.
        """
        self._base_url = _clean_url(os.environ.get("RHHI_API_URL", DEFAULT_API_URL), "RHHI_API_URL")
        self._requests_base_url = _clean_url(
            os.environ.get("RHHI_REQUESTS_API_URL", DEFAULT_REQUESTS_API_URL),
            "RHHI_REQUESTS_API_URL",
        )
        self._site_base_url = _clean_url(
            os.environ.get("RHHI_SITE_URL", DEFAULT_SITE_URL), "RHHI_SITE_URL"
        )
        parsed = urlparse(self._base_url)

        raw_timeout = os.environ.get("RHHI_TIMEOUT", "").strip()
        try:
            timeout = float(raw_timeout) if raw_timeout else DEFAULT_TIMEOUT
        except ValueError as e:
            raise ConfigurationError("RHHI_TIMEOUT must be a number of seconds") from e
        if not 0 < timeout <= MAX_TIMEOUT:
            raise ConfigurationError(f"RHHI_TIMEOUT must be between 0 and {MAX_TIMEOUT:g}")
        self._timeout = timeout

        logger.info("Configuration loaded (catalog host: %s)", parsed.hostname)

    @property
    def api_base_url(self) -> str:
        """Catalog API v1 base URL."""
        return f"{self._base_url}/v1"

    @property
    def requests_api_base_url(self) -> str:
        """Image-request API base URL (a separate gateway from the catalog)."""
        return self._requests_base_url

    @property
    def site_base_url(self) -> str:
        """Public site base URL used to build image-request deep links."""
        return self._site_base_url

    @property
    def timeout(self) -> float:
        """Per-request timeout in seconds."""
        return self._timeout

    def __repr__(self) -> str:
        return f"Config(api_url={self._base_url}, timeout={self._timeout:g})"


_config: Config | None = None


def get_config() -> Config:
    """Get the global configuration instance, creating it on first call."""
    global _config
    if _config is None:
        _config = Config()
    return _config
