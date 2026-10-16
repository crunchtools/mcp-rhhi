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
DEFAULT_TIMEOUT = 30.0
MAX_TIMEOUT = 300.0
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


class Config:
    """Catalog API location and request timeout, read from the environment."""

    def __init__(self) -> None:
        """Initialize configuration from environment variables.

        Raises:
            ConfigurationError: If an environment variable is invalid.
        """
        api_url = os.environ.get("RHHI_API_URL", DEFAULT_API_URL).strip().rstrip("/")
        parsed = urlparse(api_url)
        try:
            _ = parsed.port
        except ValueError as e:
            raise ConfigurationError("Invalid RHHI_API_URL: bad port") from e
        if not parsed.scheme or not parsed.netloc:
            raise ConfigurationError("Invalid RHHI_API_URL: must be a URL like " + DEFAULT_API_URL)
        if parsed.scheme != "https" and parsed.hostname not in LOCAL_HOSTS:
            raise ConfigurationError("RHHI_API_URL must use HTTPS for non-localhost URLs")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ConfigurationError(
                "RHHI_API_URL must not carry credentials, a query string or a fragment"
            )
        self._base_url = api_url

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
