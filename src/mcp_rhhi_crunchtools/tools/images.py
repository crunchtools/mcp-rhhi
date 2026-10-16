"""Image catalog tools: list and describe images."""

import html
import re
from typing import Any

from ..client import get_client
from ..models import segment

DEFAULT_README_CHARS = 20000

_BLOCK_TAGS = re.compile(r"</?(p|div|h[1-6]|li|ul|ol|pre|tr|table|br)\b[^>]*>", re.IGNORECASE)
_ANY_TAG = re.compile(r"<[^>]+>")
_BLANK_LINES = re.compile(r"\n\s*\n+")


def readme_to_text(readme_html: str, max_chars: int) -> tuple[str, bool]:
    """Strip the rendered README to plain text, capped at max_chars."""
    text = _BLOCK_TAGS.sub("\n", readme_html)
    text = html.unescape(_ANY_TAG.sub("", text))
    text = _BLANK_LINES.sub("\n\n", text).strip()
    if len(text) > max_chars:
        return text[:max_chars], True
    return text, False


def _summarize_image(image: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": image.get("name"),
        "summary": image.get("summary"),
        "application_category": image.get("application_category"),
        "streams": image.get("streams"),
        "deprecated_streams": image.get("deprecated_streams") or [],
        "variants": [v.get("name") for v in image.get("variants") or []],
        "architectures": image.get("architectures"),
        "latest_tag": image.get("latest_tag"),
        "pull_url": image.get("pull_url"),
    }


async def list_images(
    query: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    """List catalog images, optionally filtered by name/summary text or category."""
    listing = await get_client().get("/images")
    images: list[dict[str, Any]] = listing.get("images") or []
    categories = sorted({i.get("application_category") or "" for i in images} - {""})

    if query:
        needle = query.lower()
        images = [
            i
            for i in images
            if needle in (i.get("name") or "").lower() or needle in (i.get("summary") or "").lower()
        ]
    if category:
        wanted = category.lower()
        images = [i for i in images if (i.get("application_category") or "").lower() == wanted]

    return {
        "count": len(images),
        "categories": categories,
        "images": [_summarize_image(i) for i in images],
    }


async def get_image(
    name: str,
    include_readme: bool = False,
    readme_max_chars: int | None = None,
) -> dict[str, Any]:
    """Get one image's metadata, optionally with its README as plain text."""
    image: dict[str, Any] = await get_client().get(f"/images/{segment(name, 'name')}")
    readme_html = image.pop("readme_html", None) or ""
    if include_readme:
        text, truncated = readme_to_text(readme_html, readme_max_chars or DEFAULT_README_CHARS)
        image["readme"] = text
        image["readme_truncated"] = truncated
    return image
