"""Image request tools: list and look up Hummingbird image requests.

Image requests are sourced from Jira HUM "Image Request" stories (Ready=True)
and published on images.redhat.com/image-requests. They are served by a separate
API gateway from the image catalog, so these tools use their own client. Each
request carries a public deep link that opens it on the site.
"""

from typing import Any
from urllib.parse import quote

from ..client import get_requests_client
from ..config import get_config
from ..errors import SAFE_MESSAGE_MAX_LENGTH, NotFoundError, ValidationError

REQUESTS_PATH = "/image-requests"
MAX_AMBIGUOUS_LISTED = 10


def deep_link(key: str) -> str:
    """Public URL that opens one request on the images.redhat.com site."""
    base = get_config().site_base_url
    return f"{base}/image-requests?request={quote(key, safe='')}"


def normalize_key(value: str) -> str:
    """Map a bare number or REQ-/lowercase alias to the canonical HUM-NNNN key.

    Mirrors the images.redhat.com deep-link decoder: a ``REQ-`` prefix is the
    public alias for the underlying Jira ``HUM`` key, and a bare number is the
    key without its prefix.
    """
    key = value.strip().upper()
    if key.startswith("REQ-"):
        key = "HUM-" + key[4:]
    elif key.isdigit():
        key = "HUM-" + key
    return key


def _shape(item: dict[str, Any], *, detail: bool) -> dict[str, Any]:
    """Shape one request for output; detail adds the resolution date and status note."""
    key = item.get("id") or ""
    shaped = {
        "key": key,
        "title": item.get("summary"),
        "status": item.get("status"),
        "submitted": item.get("submitted"),
        "updated": item.get("updated"),
        "deep_link": deep_link(key) if key else None,
    }
    if detail:
        shaped["resolution_date"] = item.get("resolution_date")
        shaped["notes"] = item.get("notes")
    return shaped


async def _fetch() -> list[dict[str, Any]]:
    payload = await get_requests_client().get(REQUESTS_PATH)
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        items = payload.get("image_requests") or payload.get("requests") or []
        return [item for item in items if isinstance(item, dict)]
    return []


async def list_image_requests(
    status: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """List image requests, optionally filtered by status or a title/key substring."""
    items = await _fetch()
    if status:
        wanted = status.lower()
        items = [i for i in items if (i.get("status") or "").lower() == wanted]
    if search:
        needle = search.lower()
        items = [
            i
            for i in items
            if needle in (i.get("summary") or "").lower() or needle in (i.get("id") or "").lower()
        ]
    return {"count": len(items), "image_requests": [_shape(i, detail=False) for i in items]}


async def get_image_request(request: str) -> dict[str, Any]:
    """Get one request by HUM key (or bare number) or by image title."""
    items = await _fetch()

    key = normalize_key(request)
    for item in items:
        if (item.get("id") or "").upper() == key:
            return _shape(item, detail=True)

    needle = request.strip().lower()
    matches = [i for i in items if needle in (i.get("summary") or "").lower()]
    if len(matches) == 1:
        return _shape(matches[0], detail=True)
    if len(matches) > 1:
        keys = [m.get("id") or "?" for m in matches[:MAX_AMBIGUOUS_LISTED]]
        more = "" if len(matches) <= MAX_AMBIGUOUS_LISTED else ", ..."
        message = f"{len(matches)} requests match: {', '.join(keys)}{more}. Use the HUM key."
        raise ValidationError(message[:SAFE_MESSAGE_MAX_LENGTH])
    raise NotFoundError(request)
