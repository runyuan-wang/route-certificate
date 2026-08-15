"""Thin removable LingTai shadow-input adapter example.

The portable core never imports this module. The adapter maps caller-supplied
local aliases and descriptors into portable digest bindings. It cannot alter
certificate authority, fallback, baseline execution, or effects.
"""

from __future__ import annotations

from typing import Any

from route_certificate import RouteCertError, canonical_digest, is_valid_id, validate_json_value

ALLOWED_TELEMETRY_KEYS = {"local_run_label", "input_bytes", "output_bytes", "tool_count"}


def map_shadow_inputs(
    *,
    host_task_id: str,
    task_contract: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    telemetry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Map sanitized local aliases to portable bindings, or fail closed."""

    errors: list[str] = []
    try:
        validate_json_value(
            {
                "host_task_id": host_task_id,
                "task_contract": task_contract,
                "sources": sources,
                "telemetry": telemetry or {},
            }
        )
    except RouteCertError:
        errors.append("ADAPTER_PRIVACY_OR_SHAPE")
    if not isinstance(host_task_id, str) or not host_task_id.startswith("shadow-task-") or not is_valid_id(host_task_id):
        errors.append("BAD_HOST_TASK_ID")
    if not isinstance(task_contract, dict) or not {"id", "version"} <= set(task_contract):
        errors.append("BAD_TASK_CONTRACT")
    elif set(task_contract) - {"id", "version", "objective", "rubric_ref"}:
        errors.append("BAD_TASK_CONTRACT")
    elif not is_valid_id(task_contract.get("id")) or not isinstance(task_contract.get("version"), str):
        errors.append("BAD_TASK_CONTRACT")
    if not isinstance(sources, dict) or not sources:
        errors.append("BAD_SOURCES")
    else:
        for key, value in sources.items():
            if not isinstance(key, str) or not is_valid_id(key):
                errors.append("BAD_SOURCE_DESCRIPTOR")
                continue
            if (
                not isinstance(value, dict)
                or set(value) - {"id", "version", "title", "headings", "body_ref"}
                or value.get("id") != key
                or "version" not in value
                or not is_valid_id(value.get("id"))
                or not isinstance(value.get("version"), str)
            ):
                errors.append("BAD_SOURCE_DESCRIPTOR")
    if telemetry is not None:
        if not isinstance(telemetry, dict):
            errors.append("BAD_TELEMETRY")
        else:
            if any(not isinstance(key, str) or key not in ALLOWED_TELEMETRY_KEYS for key in telemetry):
                errors.append("UNKNOWN_TELEMETRY")
            for key in ("input_bytes", "output_bytes", "tool_count"):
                if key in telemetry and (type(telemetry[key]) is not int or telemetry[key] < 0):
                    errors.append("BAD_TELEMETRY_VALUE")
            label = telemetry.get("local_run_label")
            if label is not None and (not isinstance(label, str) or ".." in label):
                errors.append("BAD_TELEMETRY_VALUE")
    if errors:
        return {
            "adapter": "lingtai-shadow-reference",
            "status": "fail_closed",
            "errors": sorted(set(errors)),
            "authority_preserved": "advisory_only",
            "baseline_execution_required": True,
            "effects_applied": False,
        }
    return {
        "adapter": "lingtai-shadow-reference",
        "status": "pass",
        "host_task_ref": host_task_id,
        "task_binding": {
            "id": task_contract["id"],
            "version": task_contract["version"],
            "digest": canonical_digest(task_contract),
        },
        "source_bindings": [
            {"id": key, "version": value["version"], "digest": canonical_digest(value)}
            for key, value in sorted(sources.items())
        ],
        "telemetry": telemetry or {},
        "authority_preserved": "advisory_only",
        "baseline_execution_required": True,
        "effects_applied": False,
    }
