"""Input validation for tool parameters.

The schema-level types (used in server.py signatures) publish each parameter's
valid domain. The path helpers re-check and URL-encode every value before it
reaches a URL, so tools stay safe when called directly.
"""

import re
from typing import Annotated, Any, Literal
from urllib.parse import quote

from pydantic import BeforeValidator, Field, StringConstraints

from .errors import ValidationError

SLUG_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
DIGEST_PATTERN = r"^(sha256:)?[a-fA-F0-9]{64}$"
VULN_ID_PATTERN = r"^[A-Za-z]{2,5}-[A-Za-z0-9-]{4,40}$"
MAX_SLUG_LENGTH = 128
MAX_QUERY_LENGTH = 100
MAX_HISTORY_ROWS = 500
MAX_LIST_ROWS = 1000
MAX_README_CHARS = 100_000

SEVERITY_ORDER = ("critical", "high", "medium", "low", "negligible", "unknown")
SBOM_CATEGORIES = frozenset({"runtime", "build", "source"})

_SLUG_RE = re.compile(SLUG_PATTERN)
_DIGEST_RE = re.compile(DIGEST_PATTERN)


def _blank_to_none(value: Any) -> Any:
    """Map an absent optional value ("", whitespace, null) to None."""
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return value


def _lower_or_none(value: Any) -> Any:
    value = _blank_to_none(value)
    return value.lower() if isinstance(value, str) else value


def _positive_or_none(value: Any) -> Any:
    value = _blank_to_none(value)
    if isinstance(value, int) and not isinstance(value, bool) and value <= 0:
        return None
    return value


def _strip(value: Any) -> Any:
    return value.strip() if isinstance(value, str) else value


def _strip_lower(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


_SlugStr = Annotated[
    str, StringConstraints(min_length=1, max_length=MAX_SLUG_LENGTH, pattern=SLUG_PATTERN)
]
_QueryStr = Annotated[str, StringConstraints(min_length=1, max_length=MAX_QUERY_LENGTH)]

Slug = Annotated[_SlugStr, BeforeValidator(_strip)]
OptionalSlug = Annotated[_SlugStr | None, BeforeValidator(_blank_to_none)]
Digest = Annotated[
    Annotated[str, StringConstraints(pattern=DIGEST_PATTERN)], BeforeValidator(_strip_lower)
]
VulnId = Annotated[
    Annotated[str, StringConstraints(pattern=VULN_ID_PATTERN)], BeforeValidator(_strip)
]
OptionalQuery = Annotated[_QueryStr | None, BeforeValidator(_blank_to_none)]
Severity = Literal["critical", "high", "medium", "low", "negligible", "unknown"]
OptionalSeverity = Annotated[Severity | None, BeforeValidator(_lower_or_none)]
SbomCategory = Literal["runtime", "build", "source"]
OptionalSbomCategory = Annotated[SbomCategory | None, BeforeValidator(_lower_or_none)]


# Optional positive result caps; zero, negative or blank means the tool's default.
HistoryLimit = Annotated[
    Annotated[int, Field(ge=1, le=MAX_HISTORY_ROWS)] | None, BeforeValidator(_positive_or_none)
]
ListLimit = Annotated[
    Annotated[int, Field(ge=1, le=MAX_LIST_ROWS)] | None, BeforeValidator(_positive_or_none)
]
ReadmeChars = Annotated[
    Annotated[int, Field(ge=1, le=MAX_README_CHARS)] | None, BeforeValidator(_positive_or_none)
]


def segment(value: str, field: str) -> str:
    """Validate an image, stream, variant, tag or arch name and URL-encode it."""
    value = value.strip() if isinstance(value, str) else ""
    if not value or len(value) > MAX_SLUG_LENGTH or not _SLUG_RE.match(value):
        raise ValidationError(
            f"{field} must be 1-{MAX_SLUG_LENGTH} characters of letters, digits, '.', '_' or '-'"
        )
    return quote(value, safe="")


def digest_segment(value: str) -> str:
    """Validate a sha256 manifest digest; the release routes take the bare hex."""
    value = value.strip().lower() if isinstance(value, str) else ""
    if not _DIGEST_RE.match(value):
        raise ValidationError("digest must be sha256:<64 hex characters> or the bare hex")
    return value.removeprefix("sha256:")


def severity_floor(min_severity: str | None) -> frozenset[str]:
    """Severities (lowercase) at or above min_severity; all of them when None."""
    if min_severity is None:
        return frozenset(SEVERITY_ORDER)
    level = min_severity.lower()
    if level not in SEVERITY_ORDER:
        raise ValidationError(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")
    if level in ("negligible", "unknown"):
        return frozenset(SEVERITY_ORDER)
    return frozenset(SEVERITY_ORDER[: SEVERITY_ORDER.index(level) + 1])
