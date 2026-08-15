"""Reference seam for additive LingTai supervisor return observation.

This small module demonstrates the host contract; it is not a drop-in kernel
patch. A host calls ``publish_with_optional_observation`` only after terminal
truth is durable and before its ordinary terminal notification is published.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

TESTED_LINGTAI_COMMIT = "9bb869c4fd101ae1247db0e6b7839138f06abbe7"
NOTICE_SCHEMA = "lingtai.return-observation-notice.v0"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GENERATION_RE = re.compile(r"(?:g0000|g[1-9][0-9]*-[0-9a-f]{16})\Z")
_NOTICE_KEYS = {
    "schema_version",
    "state",
    "generation",
    "receipt_digest",
    "authority",
    "raw_result_unchanged",
}


def _valid_notice(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _NOTICE_KEYS
        and value.get("schema_version") == NOTICE_SCHEMA
        and value.get("state") == "available"
        and isinstance(value.get("generation"), str)
        and bool(_GENERATION_RE.fullmatch(value["generation"]))
        and isinstance(value.get("receipt_digest"), str)
        and bool(_DIGEST_RE.fullmatch(value["receipt_digest"]))
        and value.get("authority") == "advisory_only"
        and value.get("raw_result_unchanged") is True
    )


def publish_with_optional_observation(
    *,
    enabled: bool,
    raw_result: bytes,
    ordinary_notification: Mapping[str, Any],
    observe_bounded: Callable[[], Any],
) -> tuple[bytes, dict[str, Any]]:
    """Return unchanged raw bytes and an additive-only notification copy.

    Disabled mode never invokes ``observe_bounded``. Any observer exception,
    malformed notice, or unexpected value fails open to ordinary raw delivery.
    ``BaseException`` containment mirrors the tested host seam so observer
    interruption cannot suppress terminal delivery.
    """

    original = dict(ordinary_notification)
    if enabled is not True:
        return raw_result, original
    try:
        notice = observe_bounded()
        if not _valid_notice(notice):
            return raw_result, original
        augmented = dict(original)
        augmented["return_observation"] = dict(notice)
        return raw_result, augmented
    except BaseException:
        return raw_result, original
