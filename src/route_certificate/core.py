"""Portable, source-bound, advisory RouteCertificate mechanics.

The standard-library-only core does not fetch network resources, call models,
mutate host runtime state, or provide a final substantive judgment. Its
mechanical receipts prove identity, integrity, and provenance binding only;
they do not prove semantic truth, quality, security, or authorization.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

PROFILE_NAME = "routecert-canonical-json-v0"
CONSUMER_PROJECTION_PROFILE = "routecert-consumer-projection-v0"
CERT_SCHEMA_VERSION = "routecert.certificate.v0"
ENVELOPE_SCHEMA_VERSION = "routecert.decision-envelope.v0"
RECEIPT_SCHEMA_VERSION = "routecert.consumer-validation-receipt.v0"
PRODUCER_RECEIPT_SCHEMA_VERSION = "routecert.producer-receipt.v0"
PROJECTION_SCHEMA_VERSION = "routecert.projection.v0"
FALLBACK_SCHEMA_VERSION = "routecert.raw-fallback.v0"

MAX_BYTES = 256 * 1024
MAX_STRING_BYTES = 4096
MAX_DEPTH = 16
MAX_NODES = 10000
SAFE_INTEGER_MIN = -(2**53 - 1)
SAFE_INTEGER_MAX = 2**53 - 1

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
FORBIDDEN_FIELD_RE = re.compile(r"(?:^|_)(verdict|approval|approved|reject|rejection|score|recommendation)(?:_|$)")
SECRET_FIELD_RE = re.compile(r"^(?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|authorization)$", re.IGNORECASE)
JSON_POINTER_RE = re.compile(r"^(?:|(?:/(?:[^~/]|~0|~1)*)*)$")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"(?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|authorization)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16})\b"),
)
PRIVATE_PATH_PATTERNS = (
    re.compile(r"(?:^|[^A-Za-z0-9])[A-Za-z]:[\\/]"),
    re.compile(r"file:///", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])(?:\.lingtai|\.secrets|\.ssh|\.notification)(?:[\\/]|$)"),
    re.compile(r"(?:^|[\\/])(?:daemons|private|credentials)(?:[\\/]|$)"),
    re.compile(r"\bem-[0-9a-f]{4,}\b", re.IGNORECASE),
)
URL_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s<>'\"]+")
ABS_POSIX_RE = re.compile(r"(?<![A-Za-z0-9._~%+-])/(?!/)(?:[A-Za-z0-9._@+-]+/)+(?:[A-Za-z0-9._@+-]+)")

MANDATORY_CERT_KEYS = {
    "schema_version",
    "canonical_profile",
    "certificate_id",
    "created_at",
    "expires_at",
    "producer",
    "authority",
    "task_binding",
    "source_bindings",
    "rubric_binding",
    "route",
    "scope",
    "uncertainty",
    "conditions",
    "fallback",
    "validation_state",
    "lineage",
    "producer_receipt_ref",
}

PROJECTION_KEYS = {
    "schema_version",
    "canonical_profile",
    "projection_profile",
    "certificate_ref",
    "producer_receipt_ref",
    "included",
    "deferred",
    "ordered_heading_evidence_inventory",
}

ENVELOPE_KEYS = {
    "schema_version",
    "canonical_profile",
    "projection_profile",
    "consumed",
    "policy_checks",
    "included",
    "deferred",
    "producer_receipt_ref",
    "consumer_validation_receipt_ref",
    "source_availability",
    "fallback_result",
    "consumer_disposition",
    "no_final_judgment",
    "baseline_execution_required",
    "effects_applied",
}

MANDATORY_VISIBLE_PREFIXES = (
    "/schema_version",
    "/canonical_profile",
    "/certificate_id",
    "/created_at",
    "/expires_at",
    "/authority",
    "/task_binding",
    "/source_bindings",
    "/rubric_binding",
    "/route",
    "/scope",
    "/uncertainty",
    "/conditions",
    "/fallback",
    "/validation_state",
    "/producer_receipt_ref",
)


class RouteCertError(ValueError):
    """Documented error for strict parse/canonical/projection helper failures."""


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise RouteCertError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _reject_float(value: str) -> Any:
    raise RouteCertError(f"floating-point JSON number is forbidden: {value}")


def _reject_constant(value: str) -> Any:
    raise RouteCertError(f"non-finite JSON number is forbidden: {value}")


def load_json_strict(text: str | bytes) -> Any:
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RouteCertError("JSON bytes are not UTF-8") from exc
    if not isinstance(text, str):
        raise RouteCertError("JSON input must be str or bytes")
    if len(text.encode("utf-8", "surrogatepass")) > MAX_BYTES:
        raise RouteCertError("JSON exceeds bounded byte profile")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_hook,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            parse_int=int,
        )
    except json.JSONDecodeError as exc:
        raise RouteCertError(f"malformed JSON: {exc}") from exc
    _raise_if_scan_errors(value)
    return value


def canonical_bytes(value: Any) -> bytes:
    _raise_if_scan_errors(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise RouteCertError(f"object is not canonicalizable: {exc}") from exc


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate_json_value(value: Any) -> None:
    """Validate a Python value against the bounded canonical JSON profile."""

    _raise_if_scan_errors(value)


def is_valid_id(value: Any) -> bool:
    """Return whether *value* matches the portable RouteCertificate ID grammar."""

    return _id_ok(value)


def file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _raise_if_scan_errors(value: Any) -> None:
    errors: list[str] = []
    _scan_json_value(value, "", errors, 0, {"nodes": 0}, set())
    if errors:
        raise RouteCertError("; ".join(errors))


def _err(errors: list[str], code: str, path: str, message: str) -> None:
    errors.append(f"{code}:ptr={_error_path(path)}:{message}")


def _error_path(path: str) -> str:
    return (path or "/").replace("/", "~1")


def _scan_json_value(value: Any, path: str, errors: list[str], depth: int, budget: dict[str, int], active: set[int]) -> None:
    budget["nodes"] += 1
    if budget["nodes"] > MAX_NODES:
        _err(errors, "TREE_TOO_LARGE", path, "too many JSON nodes")
        return
    if depth > MAX_DEPTH:
        _err(errors, "TREE_TOO_DEEP", path, "too much nesting")
        return
    if isinstance(value, (dict, list)):
        ident = id(value)
        if ident in active:
            _err(errors, "CYCLIC_OBJECT", path, "cyclic Python container is outside JSON")
            return
        active.add(ident)
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not (SAFE_INTEGER_MIN <= value <= SAFE_INTEGER_MAX):
            _err(errors, "INTEGER_OUT_OF_RANGE", path, "integer outside routecert-canonical-json-v0 safe domain")
        return
    if isinstance(value, float):
        _err(errors, "FLOAT_FORBIDDEN", path, "floats are outside routecert-canonical-json-v0")
        return
    if isinstance(value, str):
        _scan_string(value, path, errors)
        return
    if isinstance(value, list):
        for idx, item in enumerate(value):
            _scan_json_value(item, f"{path}/{idx}", errors, depth + 1, budget, active)
        active.discard(id(value))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _err(errors, "NON_STRING_KEY", path, "JSON object key is not a string")
                continue
            _scan_string(key, f"{path}/{_escape_pointer(key)}", errors)
            if FORBIDDEN_FIELD_RE.search(key):
                _err(errors, "FORBIDDEN_FIELD", f"{path}/{_escape_pointer(key)}", "no verdict/approval/score/recommendation fields")
            if SECRET_FIELD_RE.fullmatch(key):
                _err(errors, "SECRET_SHAPED", f"{path}/{_escape_pointer(key)}", "secret-bearing field names are refused")
            _scan_json_value(item, f"{path}/{_escape_pointer(key)}", errors, depth + 1, budget, active)
        active.discard(id(value))
        return
    _err(errors, "UNSUPPORTED_TYPE", path, f"unsupported value type {type(value).__name__}")


def _scan_string(value: str, path: str, errors: list[str]) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _err(errors, "INVALID_UNICODE", path, "string contains invalid Unicode or surrogate")
        return
    if unicodedata.normalize("NFC", value) != value:
        _err(errors, "INVALID_UNICODE", path, "string must be Unicode NFC")
    if len(value.encode("utf-8")) > MAX_STRING_BYTES:
        _err(errors, "STRING_TOO_LONG", path, "string exceeds bounded profile")
    if any(ord(ch) < 32 for ch in value):
        _err(errors, "CONTROL_CHARACTER", path, "control characters are forbidden")
    for pattern in SECRET_PATTERNS:
        if pattern.search(value):
            _err(errors, "SECRET_SHAPED", path, "secret-shaped material is refused")
            break
    for pattern in PRIVATE_PATH_PATTERNS:
        if pattern.search(value):
            _err(errors, "PRIVATE_PATH", path, "private path/internal host id is refused")
            break
    pointer_position = path.endswith("/path") and bool(JSON_POINTER_RE.fullmatch(value))
    if ABS_POSIX_RE.search(URL_RE.sub("", value)) and not pointer_position:
        _err(errors, "PRIVATE_PATH", path, "absolute POSIX-like local path is refused")


def _escape_pointer(part: str) -> str:
    return part.replace("~", "~0").replace("/", "~1")


def _unescape_pointer(part: str) -> str:
    idx = 0
    while idx < len(part):
        if part[idx] == "~":
            if idx + 1 >= len(part) or part[idx + 1] not in "01":
                raise RouteCertError("invalid RFC 6901 escape sequence")
            idx += 2
        else:
            idx += 1
    return part.replace("~1", "/").replace("~0", "~")


def iter_leaf_pointers(value: Any, prefix: str = "") -> list[str]:
    _raise_if_scan_errors(value)
    if isinstance(value, dict):
        out: list[str] = []
        for key in sorted(value.keys()):
            out.extend(iter_leaf_pointers(value[key], f"{prefix}/{_escape_pointer(key)}"))
        return out
    if isinstance(value, list):
        out = []
        for idx, item in enumerate(value):
            out.extend(iter_leaf_pointers(item, f"{prefix}/{idx}"))
        return out
    return [prefix or "/"]


def get_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise RouteCertError(f"invalid JSON Pointer: {pointer!r}")
    cur = value
    for raw in pointer.split("/")[1:]:
        part = _unescape_pointer(raw)
        if isinstance(cur, list):
            if not part.isdigit():
                raise RouteCertError(f"non-numeric list pointer segment: {pointer}")
            idx = int(part)
            if idx >= len(cur):
                raise RouteCertError(f"list pointer out of range: {pointer}")
            cur = cur[idx]
        elif isinstance(cur, dict):
            if part not in cur:
                raise RouteCertError(f"object pointer not found: {pointer}")
            cur = cur[part]
        else:
            raise RouteCertError(f"pointer enters scalar: {pointer}")
    return cur


def _new_checks() -> dict[str, dict[str, Any]]:
    return {
        "structural": {"status": "pass", "errors": []},
        "referential": {"status": "pass", "errors": []},
        "closure": {"status": "pass", "errors": []},
        "artifact": {"status": "pass", "errors": []},
        "semantic": {"status": "not_performed", "errors": []},
    }


def _add(checks: dict[str, dict[str, Any]], layer: str, code: str, path: str, message: str) -> None:
    checks[layer]["errors"].append(f"{code}:ptr={_error_path(_safe_error_path(path))}:{_safe_error_message(message)}")


def _safe_error_path(path: str) -> str:
    text = str(path)
    if any(pattern.search(text) for pattern in SECRET_PATTERNS) or any(pattern.search(text) for pattern in PRIVATE_PATH_PATTERNS):
        return "/unsafe"
    if ABS_POSIX_RE.search(URL_RE.sub("", text)):
        return "/unsafe"
    return text


def _safe_error_message(message: str) -> str:
    text = str(message)
    if any(pattern.search(text) for pattern in SECRET_PATTERNS) or any(pattern.search(text) for pattern in PRIVATE_PATH_PATTERNS):
        return "details withheld"
    if ABS_POSIX_RE.search(URL_RE.sub("", text)):
        return "details withheld"
    return text


def _is_obj(value: Any) -> bool:
    return isinstance(value, dict)


def _is_list(value: Any) -> bool:
    return isinstance(value, list)


def _id_ok(value: Any) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value))


def _digest_ok(value: Any) -> bool:
    return isinstance(value, str) and bool(DIGEST_RE.fullmatch(value))


def _shape_obj(checks: dict[str, dict[str, Any]], value: Any, path: str, required: set[str], allowed: set[str]) -> bool:
    if not _is_obj(value):
        _add(checks, "structural", "BAD_TYPE", path, "object required")
        return False
    keys = set(value)
    for key in sorted(required - keys):
        _add(checks, "structural", "MISSING_FIELD", f"{path}/{key}", "required field missing")
    for key in sorted((key for key in keys - allowed if isinstance(key, str)), key=repr):
        _add(checks, "structural", "UNKNOWN_FIELD", f"{path}/{key}", "unknown field refused")
    for key in (key for key in keys if not isinstance(key, str)):
        _add(checks, "structural", "NON_STRING_KEY", path, "object key must be string")
    return not (required - keys)


def validate_certificate(
    cert: Any,
    *,
    task: Any,
    sources: Any,
    rubric: Any | None,
    producer_receipt: Any,
    artifact_root: str | Path | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Return a fail-closed current consumer validation receipt for hostile inputs."""

    checks = _new_checks()
    invalid_inputs: set[str] = set()
    for name, value in (("certificate", cert), ("task", task), ("sources", sources), ("rubric", rubric), ("producer_receipt", producer_receipt)):
        try:
            if value is not None:
                _raise_if_scan_errors(value)
        except RouteCertError as exc:
            invalid_inputs.add(name)
            _add(checks, "structural", "MALFORMED_INPUT", f"/{name}", "input rejected by strict scanner")
            for part in str(exc).split("; "):
                if ":" in part:
                    code = part.split(":", 1)[0]
                    checks["structural"]["errors"].append(f"{code}:ptr={_error_path('/' + name)}:strict scanner rejected unsafe input")

    if not _is_obj(cert):
        _add(checks, "structural", "BAD_TYPE", "/certificate", "certificate object required")
        return _finish_receipt(checks, cert, task, sources, rubric, producer_receipt)
    _shape_obj(checks, cert, "/", MANDATORY_CERT_KEYS, MANDATORY_CERT_KEYS)
    if cert.get("schema_version") != CERT_SCHEMA_VERSION:
        _add(checks, "structural", "UNSUPPORTED_SCHEMA", "/schema_version", "unsupported certificate schema")
    if cert.get("canonical_profile") != PROFILE_NAME:
        _add(checks, "structural", "PROFILE_MISMATCH", "/canonical_profile", "unsupported canonical profile")
    if not _id_ok(cert.get("certificate_id")):
        _add(checks, "structural", "BAD_ID", "/certificate_id", "invalid certificate id")

    _validate_producer(cert.get("producer"), checks)
    _validate_object_id_version(task, cert.get("task_binding"), "TASK", "/task_binding", checks)
    if cert.get("rubric_binding") is not None:
        _validate_object_id_version(rubric, cert.get("rubric_binding"), "RUBRIC", "/rubric_binding", checks)

    source_bindings = cert.get("source_bindings")
    if not _is_list(source_bindings):
        _add(checks, "structural", "BAD_TYPE", "/source_bindings", "array required")
        source_bindings = []
    if not source_bindings:
        _add(checks, "referential", "EMPTY_SOURCE_BINDINGS", "/source_bindings", "at least one source binding required")
    if not _is_obj(sources):
        _add(checks, "referential", "BAD_SOURCES", "/sources", "sources mapping required")
        sources = {}
    seen_source_ids: set[str] = set()
    for idx, binding in enumerate(source_bindings):
        if not _is_obj(binding):
            _add(checks, "structural", "BAD_TYPE", f"/source_bindings/{idx}", "source binding object required")
            continue
        sid = binding.get("id")
        if not _id_ok(sid):
            _add(checks, "structural", "BAD_ID", f"/source_bindings/{idx}/id", "source id must match portable ID grammar")
            continue
        if sid in seen_source_ids:
            _add(checks, "referential", "DUPLICATE_SOURCE_BINDING", f"/source_bindings/{idx}/id", "duplicate source binding")
        seen_source_ids.add(sid)
        if sid not in sources:
            _add(checks, "referential", "SOURCE_UNRESOLVED", f"/source_bindings/{idx}", "source id is not supplied")
        else:
            _validate_object_id_version(sources[sid], binding, "SOURCE", f"/source_bindings/{idx}", checks)
    for key in list(sources):
        if not isinstance(key, str):
            _add(checks, "referential", "BAD_SOURCE_KEY", "/sources", "source mapping keys must be strings")
        elif not _id_ok(key):
            _add(checks, "referential", "BAD_SOURCE_KEY", "/sources", "source mapping keys must match portable ID grammar")
    extra_sources = sorted((key for key in set(sources) - {sid for sid in seen_source_ids if isinstance(sid, str)} if isinstance(key, str)), key=repr)
    for sid in extra_sources:
        _add(checks, "referential", "UNBOUND_EXTRA_SOURCE", f"/sources/{sid}", "source supplied but not certificate-bound")

    _validate_authority(cert.get("authority"), checks)
    _validate_time_order(cert, now, checks)
    _validate_route(cert.get("route"), checks)
    _validate_scope(cert.get("scope"), checks)
    _validate_uncertainty_conditions_lineage(cert, checks)
    _validate_validation_state(cert.get("validation_state"), checks)
    if "producer_receipt" in invalid_inputs:
        _add(checks, "referential", "PRODUCER_RECEIPT_INVALID", "/producer_receipt_ref", "producer receipt is malformed")
    else:
        _validate_producer_receipt(cert.get("producer_receipt_ref"), producer_receipt, checks, artifact_root)
    _validate_fallback(cert.get("fallback"), sources, checks, artifact_root)

    return _finish_receipt(checks, cert, task, sources, rubric, producer_receipt)


def _finish_receipt(checks: dict[str, dict[str, Any]], cert: Any, task: Any, sources: Any, rubric: Any, producer_receipt: Any) -> dict[str, Any]:
    overall = "pass"
    for layer, check in checks.items():
        if check["errors"]:
            check["status"] = "fail" if layer != "semantic" else "not_performed"
            overall = "fail"
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_id": "current-consumer-validation",
        "canonical_profile": PROFILE_NAME,
        "overall": overall,
        "subject_digests": {
            "certificate": _safe_digest(cert),
            "task": _safe_digest(task),
            "sources": _safe_digest(sources),
            "rubric": None if rubric is None else _safe_digest(rubric),
            "producer_receipt": _safe_digest(producer_receipt),
        },
        "checks": checks,
        "semantic_limit": "not_performed; mechanical validation is not semantic truth",
        "receipt_body_separate": True,
    }
    receipt["digest"] = canonical_digest({k: v for k, v in receipt.items() if k != "digest"})
    return receipt


def _safe_digest(value: Any) -> str | None:
    try:
        return canonical_digest(value)
    except RouteCertError:
        return None


def _validate_object_id_version(obj: Any, binding: Any, label: str, path: str, checks: dict[str, dict[str, Any]]) -> None:
    if not _is_obj(binding):
        _add(checks, "structural", "BAD_TYPE", path, "binding object required")
        return
    required = {"id", "version", "digest"}
    keys = set(binding)
    if keys != required:
        for key in sorted((key for key in keys - required if isinstance(key, str)), key=repr):
            _add(checks, "structural", "UNKNOWN_FIELD", f"{path}/{key}", "binding has unknown field")
        for key in (key for key in keys if not isinstance(key, str)):
            _add(checks, "structural", "NON_STRING_KEY", path, "binding key must be string")
    for key in ("id", "version", "digest"):
        if key not in binding:
            _add(checks, "structural", "MISSING_FIELD", f"{path}/{key}", "binding field missing")
    if not _id_ok(binding.get("id")):
        _add(checks, "structural", "BAD_ID", f"{path}/id", "binding id must match portable ID grammar")
    if not isinstance(binding.get("version"), str):
        _add(checks, "structural", "BAD_TYPE", f"{path}/version", "binding version string required")
    if not _digest_ok(binding.get("digest")):
        _add(checks, "structural", "BAD_DIGEST", f"{path}/digest", "binding digest required")
    if not _is_obj(obj):
        _add(checks, "referential", f"{label}_UNRESOLVED", path, "bound object missing")
        return
    if not _id_ok(obj.get("id")):
        _add(checks, "referential", f"{label}_BAD_ID", f"{path}/id", "bound object id must match portable ID grammar")
    if binding.get("id") != obj.get("id"):
        _add(checks, "referential", f"{label}_ID_MISMATCH", f"{path}/id", "binding id differs from object id")
    if binding.get("version") != obj.get("version"):
        _add(checks, "referential", f"{label}_VERSION_MISMATCH", f"{path}/version", "binding version differs from object version")
    try:
        actual = canonical_digest(obj)
    except RouteCertError as exc:
        _add(checks, "referential", f"{label}_DIGEST_UNAVAILABLE", path, str(exc))
        return
    if binding.get("digest") != actual:
        _add(checks, "referential", f"{label}_DIGEST_MISMATCH", f"{path}/digest", "binding digest differs from object canonical digest")


def _validate_producer(producer: Any, checks: dict[str, dict[str, Any]]) -> None:
    if not _shape_obj(checks, producer, "/producer", {"role", "identity_ref"}, {"role", "identity_ref"}):
        return
    for key in ("role", "identity_ref"):
        if not isinstance(producer.get(key), str):
            _add(checks, "structural", "BAD_TYPE", f"/producer/{key}", "string required")


def _validate_authority(authority: Any, checks: dict[str, dict[str, Any]]) -> None:
    if not _shape_obj(checks, authority, "/authority", {"mode", "contains_final_judgment", "consumer_responsibility"}, {"mode", "contains_final_judgment", "consumer_responsibility"}):
        return
    if authority.get("mode") != "advisory_only" or authority.get("contains_final_judgment") is not False:
        _add(checks, "structural", "AUTHORITY_OVERRIDE", "/authority", "certificate must remain advisory and no-verdict")
    if not isinstance(authority.get("consumer_responsibility"), str):
        _add(checks, "structural", "BAD_TYPE", "/authority/consumer_responsibility", "string required")


def _validate_time_order(cert: dict[str, Any], now: str | None, checks: dict[str, dict[str, Any]]) -> None:
    try:
        created = _parse_utc(cert.get("created_at"))
        expires = _parse_utc(cert.get("expires_at"))
        current = datetime.now(timezone.utc) if now is None else _parse_utc(now)
    except RouteCertError as exc:
        _add(checks, "closure", "BAD_TIME", "/created_at", str(exc))
        return
    if expires <= created:
        _add(checks, "closure", "BAD_TIME_ORDER", "/expires_at", "expires_at must be after created_at")
    if created > current:
        _add(checks, "closure", "FUTURE_CERTIFICATE", "/created_at", "created_at is later than current validation time")
    if current >= expires:
        _add(checks, "closure", "STALE_CERTIFICATE", "/expires_at", "certificate is expired/stale")


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise RouteCertError("timestamp must match YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise RouteCertError("timestamp is malformed") from exc


def _validate_route(route: Any, checks: dict[str, dict[str, Any]]) -> None:
    if not _shape_obj(checks, route, "/route", {"ordered_stages", "risk_order", "heading_evidence_inventory"}, {"ordered_stages", "risk_order", "heading_evidence_inventory"}):
        return
    for name in ("ordered_stages", "risk_order", "heading_evidence_inventory"):
        if not _is_list(route.get(name)) or not route.get(name):
            _add(checks, "structural", "BAD_TYPE", f"/route/{name}", "nonempty array required")
    for name in ("ordered_stages", "risk_order"):
        if _is_list(route.get(name)):
            for idx, item in enumerate(route[name]):
                if not isinstance(item, str):
                    _add(checks, "structural", "BAD_TYPE", f"/route/{name}/{idx}", "string item required")
    seen_pairs = set()
    for idx, item in enumerate(route.get("heading_evidence_inventory", []) if _is_list(route.get("heading_evidence_inventory")) else []):
        if not _is_obj(item):
            _add(checks, "structural", "BAD_TYPE", f"/route/heading_evidence_inventory/{idx}", "inventory item object required")
            continue
        if set(item) != {"heading", "evidence_refs"} or not isinstance(item.get("heading"), str) or not _is_list(item.get("evidence_refs")):
            _add(checks, "structural", "BAD_INVENTORY_ITEM", f"/route/heading_evidence_inventory/{idx}", "heading and evidence_refs required")
            continue
        refs_ok = True
        for ref_idx, ref in enumerate(item["evidence_refs"]):
            if not isinstance(ref, str):
                _add(checks, "structural", "BAD_INVENTORY_ITEM", f"/route/heading_evidence_inventory/{idx}/evidence_refs/{ref_idx}", "evidence refs must be strings")
                refs_ok = False
                continue
            if not _id_ok(ref):
                _add(checks, "structural", "BAD_ID", f"/route/heading_evidence_inventory/{idx}/evidence_refs/{ref_idx}", "evidence ref id must match portable ID grammar")
                refs_ok = False
        if not refs_ok:
            continue
        pair = (item["heading"], tuple(item["evidence_refs"]))
        if pair in seen_pairs:
            _add(checks, "structural", "DUPLICATE_INVENTORY_ENTRY", f"/route/heading_evidence_inventory/{idx}", "duplicate ordered inventory entry")
        seen_pairs.add(pair)


def _validate_scope(scope: Any, checks: dict[str, dict[str, Any]]) -> None:
    if not _shape_obj(checks, scope, "/scope", {"in_scope", "out_of_scope"}, {"in_scope", "out_of_scope"}):
        return
    for key in ("in_scope", "out_of_scope"):
        if not _is_list(scope.get(key)):
            _add(checks, "structural", "BAD_TYPE", f"/scope/{key}", "array required")
        else:
            for idx, item in enumerate(scope[key]):
                if not isinstance(item, str):
                    _add(checks, "structural", "BAD_TYPE", f"/scope/{key}/{idx}", "string item required")


def _validate_uncertainty_conditions_lineage(cert: dict[str, Any], checks: dict[str, dict[str, Any]]) -> None:
    uncertainty = cert.get("uncertainty")
    if _shape_obj(checks, uncertainty, "/uncertainty", {"unknown", "not_checked", "uncontrolled"}, {"unknown", "not_checked", "uncontrolled"}):
        for field in ("unknown", "not_checked", "uncontrolled"):
            if not _is_list(uncertainty.get(field)):
                _add(checks, "structural", "BAD_TYPE", f"/uncertainty/{field}", "array required")
            elif uncertainty.get(field):
                _add(checks, "closure", field.upper(), f"/uncertainty/{field}", "requires full material")
    conditions = cert.get("conditions")
    if _shape_obj(checks, conditions, "/conditions", {"no_go", "conflicts", "staleness", "reopen"}, {"no_go", "conflicts", "staleness", "reopen"}):
        for field in ("no_go", "conflicts", "staleness", "reopen"):
            if not _is_list(conditions.get(field)):
                _add(checks, "structural", "BAD_TYPE", f"/conditions/{field}", "array required")
            elif conditions.get(field):
                _add(checks, "closure", field.upper(), f"/conditions/{field}", "requires reopen or fail closed")
    lineage = cert.get("lineage")
    if _shape_obj(checks, lineage, "/lineage", {"conceptual_lineage", "dependencies"}, {"conceptual_lineage", "dependencies"}):
        if not isinstance(lineage.get("conceptual_lineage"), str):
            _add(checks, "structural", "BAD_TYPE", "/lineage/conceptual_lineage", "string required")
        if not _is_list(lineage.get("dependencies")):
            _add(checks, "structural", "BAD_TYPE", "/lineage/dependencies", "array required")
        elif lineage.get("dependencies"):
            _add(checks, "closure", "LINEAGE_DEPENDENCY", "/lineage/dependencies", "nonempty lineage/dependency requires full material")
            if _has_cycle(lineage["dependencies"]):
                _add(checks, "structural", "CYCLIC_LINEAGE", "/lineage/dependencies", "dependency/supersession graph is cyclic")


def _has_cycle(edges: Any) -> bool:
    if not isinstance(edges, list):
        return False
    graph: dict[str, list[str]] = {}
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != {"from", "to"} or not isinstance(edge.get("from"), str) or not isinstance(edge.get("to"), str):
            return True
        src = edge.get("from")
        dst = edge.get("to")
        graph.setdefault(src, []).append(dst)
    visited: set[str] = set()
    for start in list(graph):
        if start in visited:
            continue
        stack: list[tuple[str, int]] = [(start, 0)]
        active: set[str] = set()
        while stack:
            node, index = stack[-1]
            if node not in active and node not in visited:
                active.add(node)
            neighbors = graph.get(node, [])
            if index >= len(neighbors):
                active.discard(node)
                visited.add(node)
                stack.pop()
                continue
            nxt = neighbors[index]
            stack[-1] = (node, index + 1)
            if nxt in active:
                return True
            if nxt not in visited:
                stack.append((nxt, 0))
    return False


def _validate_validation_state(state: Any, checks: dict[str, dict[str, Any]]) -> None:
    if not _shape_obj(checks, state, "/validation_state", {"structural", "referential", "closure", "artifact", "semantic"}, {"structural", "referential", "closure", "artifact", "semantic"}):
        return
    for field in ("structural", "referential", "closure", "artifact"):
        if state.get(field) != "pass":
            _add(checks, "closure", "UNRESOLVED_VALIDATION", f"/validation_state/{field}", "non-passing validation state triggers fail closed")
    if state.get("semantic") != "not_performed":
        _add(checks, "closure", "SEMANTIC_CLAIM", "/validation_state/semantic", "Gate-0 cannot claim semantic validation")


def _validate_producer_receipt(ref: Any, producer_receipt: Any, checks: dict[str, dict[str, Any]], artifact_root: str | Path | None) -> None:
    required = {"id", "version", "digest", "relative_ref", "artifact_sha256"}
    if not _shape_obj(checks, ref, "/producer_receipt_ref", required, required):
        return
    if not _is_obj(producer_receipt):
        _add(checks, "referential", "PRODUCER_RECEIPT_UNRESOLVED", "/producer_receipt_ref", "producer receipt object missing")
        return
    if not _id_ok(ref.get("id")):
        _add(checks, "structural", "BAD_ID", "/producer_receipt_ref/id", "producer receipt ref id must match portable ID grammar")
    if not isinstance(ref.get("version"), str):
        _add(checks, "structural", "BAD_TYPE", "/producer_receipt_ref/version", "producer receipt ref version string required")
    if not _digest_ok(ref.get("digest")):
        _add(checks, "structural", "BAD_DIGEST", "/producer_receipt_ref/digest", "producer receipt ref digest required")
    if ref.get("id") != producer_receipt.get("receipt_id"):
        _add(checks, "referential", "PRODUCER_RECEIPT_ID_MISMATCH", "/producer_receipt_ref/id", "producer receipt id mismatch")
    if ref.get("version") != producer_receipt.get("schema_version"):
        _add(checks, "referential", "PRODUCER_RECEIPT_VERSION_MISMATCH", "/producer_receipt_ref/version", "producer receipt version mismatch")
    if ref.get("digest") != canonical_digest(producer_receipt):
        _add(checks, "referential", "PRODUCER_RECEIPT_DIGEST_MISMATCH", "/producer_receipt_ref/digest", "producer receipt canonical digest mismatch")
    _verify_relative_artifact(ref.get("relative_ref"), ref.get("artifact_sha256"), artifact_root, "/producer_receipt_ref", checks)
    _verify_producer_receipt_artifact(ref, producer_receipt, artifact_root, checks)


def _validate_fallback(fallback: Any, sources: dict[str, Any], checks: dict[str, dict[str, Any]], artifact_root: str | Path | None) -> None:
    if not _shape_obj(checks, fallback, "/fallback", {"raw_source_refs", "missing_or_mismatch_behavior"}, {"raw_source_refs", "missing_or_mismatch_behavior"}):
        return
    if not isinstance(fallback.get("missing_or_mismatch_behavior"), str):
        _add(checks, "structural", "BAD_TYPE", "/fallback/missing_or_mismatch_behavior", "string required")
    refs = fallback.get("raw_source_refs")
    if not _is_list(refs) or not refs:
        _add(checks, "referential", "MISSING_RAW_FALLBACK", "/fallback/raw_source_refs", "raw/full source fallback is mandatory")
        return
    seen = set()
    for idx, ref in enumerate(refs):
        path = f"/fallback/raw_source_refs/{idx}"
        required = {"id", "relative_ref", "digest", "artifact_sha256"}
        if not _shape_obj(checks, ref, path, required, required):
            continue
        sid = ref.get("id")
        if not _id_ok(sid):
            _add(checks, "structural", "BAD_ID", f"{path}/id", "fallback source id must match portable ID grammar")
            continue
        if sid in seen:
            _add(checks, "referential", "DUPLICATE_RAW_SOURCE_REF", f"{path}/id", "duplicate fallback source")
        seen.add(sid)
        if sid not in sources:
            _add(checks, "referential", "RAW_SOURCE_UNRESOLVED", path, "fallback source id is not bound")
        else:
            try:
                descriptor_digest = canonical_digest(sources[sid])
            except RouteCertError as exc:
                _add(checks, "referential", "RAW_SOURCE_DESCRIPTOR_DIGEST_UNAVAILABLE", f"{path}/digest", str(exc))
            else:
                if ref.get("digest") != descriptor_digest:
                    _add(checks, "referential", "RAW_SOURCE_DESCRIPTOR_DIGEST_MISMATCH", f"{path}/digest", "fallback descriptor digest mismatch")
        _verify_relative_artifact(ref.get("relative_ref"), ref.get("artifact_sha256"), artifact_root, path, checks)


def _verify_relative_artifact(relative_ref: Any, expected_sha256: Any, artifact_root: str | Path | None, path: str, checks: dict[str, dict[str, Any]]) -> None:
    if not isinstance(relative_ref, str) or PurePosixPath(relative_ref).is_absolute() or ".." in PurePosixPath(relative_ref).parts:
        _add(checks, "artifact", "PATH_CONTAINMENT", f"{path}/relative_ref", "contained relative path required")
        return
    if "\x00" in relative_ref:
        _add(checks, "artifact", "PATH_CONTAINMENT", f"{path}/relative_ref", "NUL byte in path is refused")
        return
    if not _digest_ok(expected_sha256):
        _add(checks, "artifact", "BAD_ARTIFACT_DIGEST", f"{path}/artifact_sha256", "sha256 digest required")
        return
    if artifact_root is None:
        _add(checks, "artifact", "ARTIFACT_ROOT_MISSING", path, "artifact root is required for availability")
        return
    try:
        root = Path(artifact_root).resolve()
        candidate = root / relative_ref
        if candidate.is_symlink():
            _add(checks, "artifact", "ARTIFACT_UNAVAILABLE", f"{path}/relative_ref", "artifact file unavailable or symlink")
            return
        target = candidate.resolve()
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        _add(checks, "artifact", "ARTIFACT_PATH_ERROR", f"{path}/relative_ref", f"path resolution failed: {type(exc).__name__}")
        return
    try:
        target.relative_to(root)
    except ValueError:
        _add(checks, "artifact", "PATH_CONTAINMENT", f"{path}/relative_ref", "artifact escapes root")
        return
    try:
        is_file = target.is_file()
        is_symlink = target.is_symlink()
    except (OSError, ValueError) as exc:
        _add(checks, "artifact", "ARTIFACT_PATH_ERROR", f"{path}/relative_ref", f"artifact stat failed: {type(exc).__name__}")
        return
    if not is_file or is_symlink:
        _add(checks, "artifact", "ARTIFACT_UNAVAILABLE", f"{path}/relative_ref", "artifact file unavailable or symlink")
        return
    try:
        got = file_sha256(target)
    except (OSError, ValueError) as exc:
        _add(checks, "artifact", "ARTIFACT_READ_ERROR", f"{path}/relative_ref", f"artifact read failed: {type(exc).__name__}")
        return
    if got != expected_sha256:
        _add(checks, "artifact", "ARTIFACT_DIGEST_MISMATCH", f"{path}/artifact_sha256", "artifact byte digest mismatch")


def _verify_producer_receipt_artifact(ref: dict[str, Any], producer_receipt: dict[str, Any], artifact_root: str | Path | None, checks: dict[str, dict[str, Any]]) -> None:
    path = "/producer_receipt_ref"
    relative_ref = ref.get("relative_ref")
    expected_sha256 = ref.get("artifact_sha256")
    if not isinstance(relative_ref, str) or PurePosixPath(relative_ref).is_absolute() or ".." in PurePosixPath(relative_ref).parts:
        return
    if "\x00" in relative_ref or not _digest_ok(expected_sha256) or artifact_root is None:
        return
    try:
        root = Path(artifact_root).resolve()
        candidate = root / relative_ref
        if candidate.is_symlink():
            return
        target = candidate.resolve()
        target.relative_to(root)
        if not target.is_file() or target.is_symlink():
            return
        raw = target.read_bytes()
    except (OSError, ValueError, RuntimeError, TypeError):
        return
    if "sha256:" + hashlib.sha256(raw).hexdigest() != expected_sha256:
        return
    try:
        artifact_receipt = load_json_strict(raw)
    except RouteCertError:
        _add(checks, "artifact", "PRODUCER_RECEIPT_ARTIFACT_MISMATCH", path, "producer receipt artifact is not strict canonical JSON material")
        return
    try:
        artifact_digest = canonical_digest(artifact_receipt)
        memory_digest = canonical_digest(producer_receipt)
    except RouteCertError:
        _add(checks, "artifact", "PRODUCER_RECEIPT_ARTIFACT_MISMATCH", path, "producer receipt artifact or object digest unavailable")
        return
    if artifact_digest != memory_digest or artifact_digest != ref.get("digest"):
        _add(checks, "artifact", "PRODUCER_RECEIPT_ARTIFACT_MISMATCH", path, "producer receipt artifact does not match bound receipt digest")
    if isinstance(artifact_receipt, dict):
        if artifact_receipt.get("receipt_id") != ref.get("id") or artifact_receipt.get("schema_version") != ref.get("version"):
            _add(checks, "artifact", "PRODUCER_RECEIPT_ARTIFACT_MISMATCH", path, "producer receipt artifact id or version does not match reference")
    else:
        _add(checks, "artifact", "PRODUCER_RECEIPT_ARTIFACT_MISMATCH", path, "producer receipt artifact object required")


def mandatory_projection_pointers(cert: dict[str, Any]) -> list[str]:
    leaves = iter_leaf_pointers(cert)
    include = []
    for pointer in leaves:
        if any(pointer == prefix or pointer.startswith(prefix + "/") for prefix in MANDATORY_VISIBLE_PREFIXES):
            include.append(pointer)
    return sorted(include)


def build_projection(cert: Any, include_paths: list[str] | None = None) -> dict[str, Any]:
    """Unsafe compatibility helper. Envelopes reject non-profile projections."""

    if include_paths is None:
        return build_profile_projection(cert)
    _raise_if_scan_errors(cert)
    if not isinstance(cert, dict):
        raise RouteCertError("certificate object required")
    _validate_include_paths(include_paths)
    return _build_projection(cert, include_paths, projection_profile="unsafe-caller-selected")


def build_profile_projection(cert: Any) -> dict[str, Any]:
    _raise_if_scan_errors(cert)
    if not isinstance(cert, dict):
        raise RouteCertError("certificate object required")
    return _build_projection(cert, mandatory_projection_pointers(cert), projection_profile=CONSUMER_PROJECTION_PROFILE)


def _build_projection(cert: dict[str, Any], include_paths: list[str], *, projection_profile: str) -> dict[str, Any]:
    _validate_include_paths(include_paths)
    all_paths = iter_leaf_pointers(cert)
    all_set = set(all_paths)
    for pointer in include_paths:
        if pointer not in all_set:
            raise RouteCertError(f"projection includes unknown JSON Pointer: {pointer}")
    included = [{"path": path, "value": get_pointer(cert, path)} for path in sorted(include_paths)]
    deferred = [{"path": path, "digest": canonical_digest(get_pointer(cert, path))} for path in sorted(all_set - set(include_paths))]
    return {
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "canonical_profile": PROFILE_NAME,
        "projection_profile": projection_profile,
        "certificate_ref": {"id": cert.get("certificate_id"), "digest": canonical_digest(cert)},
        "producer_receipt_ref": {
            "id": cert.get("producer_receipt_ref", {}).get("id") if isinstance(cert.get("producer_receipt_ref"), dict) else None,
            "digest": cert.get("producer_receipt_ref", {}).get("digest") if isinstance(cert.get("producer_receipt_ref"), dict) else None,
        },
        "included": included,
        "deferred": deferred,
        "ordered_heading_evidence_inventory": get_pointer(cert, "/route/heading_evidence_inventory"),
    }


def _validate_include_paths(include_paths: Any) -> None:
    if not isinstance(include_paths, list):
        raise RouteCertError("include_paths must be a list of JSON Pointer strings")
    if not all(isinstance(path, str) for path in include_paths):
        raise RouteCertError("include_paths must contain only JSON Pointer strings")
    if len(include_paths) != len(set(include_paths)):
        raise RouteCertError("duplicate include paths")


def verify_projection_equivalence(cert: Any, projection: Any) -> dict[str, Any]:
    errors: list[str] = []
    try:
        _raise_if_scan_errors(cert)
        if not isinstance(cert, dict) or not isinstance(projection, dict):
            raise RouteCertError("certificate and projection objects required")
        if set(projection) != PROJECTION_KEYS:
            errors.append("PROJECTION_SHAPE_MISMATCH:/")
        if projection.get("schema_version") != PROJECTION_SCHEMA_VERSION:
            errors.append("UNSUPPORTED_PROJECTION_SCHEMA:/schema_version")
        if projection.get("canonical_profile") != PROFILE_NAME:
            errors.append("PROJECTION_PROFILE_MISMATCH:/canonical_profile")
        if projection.get("projection_profile") != CONSUMER_PROJECTION_PROFILE:
            errors.append("UNSAFE_PROJECTION_PROFILE:/projection_profile")
        cert_ref = projection.get("certificate_ref")
        if not isinstance(cert_ref, dict) or set(cert_ref) != {"id", "digest"}:
            errors.append("CERTIFICATE_REF_SHAPE:/certificate_ref")
        else:
            if cert_ref.get("id") != cert.get("certificate_id"):
                errors.append("CERTIFICATE_ID_MISMATCH:/certificate_ref/id")
            if cert_ref.get("digest") != canonical_digest(cert):
                errors.append("CERTIFICATE_DIGEST_MISMATCH:/certificate_ref/digest")
        prod_ref = projection.get("producer_receipt_ref")
        cert_prod_ref = cert.get("producer_receipt_ref", {})
        if not isinstance(cert_prod_ref, dict):
            cert_prod_ref = {}
            errors.append("CERTIFICATE_PRODUCER_RECEIPT_REF_SHAPE:/producer_receipt_ref")
        if not isinstance(prod_ref, dict) or set(prod_ref) != {"id", "digest"}:
            errors.append("PRODUCER_RECEIPT_REF_SHAPE:/producer_receipt_ref")
        else:
            if prod_ref.get("id") != cert_prod_ref.get("id"):
                errors.append("PRODUCER_RECEIPT_ID_MISMATCH:/producer_receipt_ref/id")
            if prod_ref.get("digest") != cert_prod_ref.get("digest"):
                errors.append("PRODUCER_RECEIPT_DIGEST_MISMATCH:/producer_receipt_ref/digest")
        included = projection.get("included")
        deferred = projection.get("deferred")
        if not isinstance(included, list) or not isinstance(deferred, list):
            errors.append("PROJECTION_LIST_SHAPE:/included/deferred")
            return {"status": "fail", "errors": errors}
        inc_paths = [item.get("path") if isinstance(item, dict) else None for item in included]
        def_paths = [item.get("path") if isinstance(item, dict) else None for item in deferred]
        if not all(isinstance(path, str) for path in inc_paths):
            errors.append("INCLUDED_PATH_TYPE:/included")
        if not all(isinstance(path, str) for path in def_paths):
            errors.append("DEFERRED_PATH_TYPE:/deferred")
        str_inc_paths = [path for path in inc_paths if isinstance(path, str)]
        str_def_paths = [path for path in def_paths if isinstance(path, str)]
        if len(str_inc_paths) != len(set(str_inc_paths)):
            errors.append("DUPLICATE_INCLUDED_PATH:/included")
        if len(str_def_paths) != len(set(str_def_paths)):
            errors.append("DUPLICATE_DEFERRED_PATH:/deferred")
        all_paths = set(iter_leaf_pointers(cert))
        if set(str_inc_paths) | set(str_def_paths) != all_paths or set(str_inc_paths) & set(str_def_paths):
            errors.append("FIELD_COVERAGE_MISMATCH:/included/deferred")
        mandatory = set(mandatory_projection_pointers(cert))
        if not mandatory.issubset(set(str_inc_paths)):
            errors.append("MANDATORY_FIELD_DEFERRED:/included")
        projected_path_set = set()
        for idx, item in enumerate(included):
            if not isinstance(item, dict) or set(item) != {"path", "value"}:
                errors.append(f"INCLUDED_SHAPE:/included/{idx}")
                continue
            path = item["path"]
            if not isinstance(path, str):
                errors.append(f"INCLUDED_PATH_TYPE:/included/{idx}/path")
                continue
            projected_path_set.add(path)
            if path not in all_paths:
                errors.append(f"INCLUDED_UNKNOWN:/included/{idx}/path")
                continue
            if item["value"] != get_pointer(cert, path):
                errors.append(f"INCLUDED_VALUE_MISMATCH:/included/{idx}/value")
        if projected_path_set != set(str_inc_paths):
            errors.append("EXTRA_OR_MISSING_PROJECTED_FIELD:/included")
        for idx, item in enumerate(deferred):
            if not isinstance(item, dict) or set(item) != {"path", "digest"}:
                errors.append(f"DEFERRED_SHAPE:/deferred/{idx}")
                continue
            path = item["path"]
            if not isinstance(path, str):
                errors.append(f"DEFERRED_PATH_TYPE:/deferred/{idx}/path")
                continue
            if path not in all_paths:
                errors.append(f"DEFERRED_UNKNOWN:/deferred/{idx}/path")
                continue
            if item["digest"] != canonical_digest(get_pointer(cert, path)):
                errors.append(f"DEFERRED_DIGEST_MISMATCH:/deferred/{idx}/digest")
        try:
            inventory = get_pointer(cert, "/route/heading_evidence_inventory")
        except RouteCertError as exc:
            errors.append(f"CERTIFICATE_ROUTE_SHAPE:/route/heading_evidence_inventory:{exc}")
            inventory = None
        if projection.get("ordered_heading_evidence_inventory") != inventory:
            errors.append("ORDERED_INVENTORY_MISMATCH:/ordered_heading_evidence_inventory")
    except RouteCertError as exc:
        errors.append(f"PROJECTION_EXCEPTION:/:{exc}")
    return {"status": "pass" if not errors else "fail", "errors": errors}


def resolve_fallback(cert: Any, sources: Any, *, artifact_root: str | Path | None = None, prior_loaded: bool = False) -> dict[str, Any]:
    checks = _new_checks()
    if isinstance(cert, dict) and isinstance(sources, dict):
        _validate_fallback(cert.get("fallback"), sources, checks, artifact_root)
    else:
        _add(checks, "artifact", "BAD_INPUT", "/", "certificate and sources mapping required")
    if isinstance(cert, dict) and not isinstance(cert.get("conditions", {}), dict):
        _add(checks, "artifact", "BAD_CONDITIONS", "/conditions", "conditions object required")
    errors = [item for check in checks.values() for item in check["errors"]]
    available = not errors
    trigger = _fallback_trigger_present(cert)
    if prior_loaded:
        transition = "already_loaded"
    elif not available:
        transition = "fail_closed_unavailable"
    elif trigger:
        transition = "load_full_material"
    else:
        transition = "not_loaded"
    return {
        "schema_version": FALLBACK_SCHEMA_VERSION,
        "raw_source_available": available,
        "complete_source_available": available,
        "transition": transition,
        "errors": errors,
    }


def _fallback_trigger_present(cert: Any) -> bool:
    if not isinstance(cert, dict):
        return True
    conditions = cert.get("conditions")
    if isinstance(conditions, dict):
        for field in ("no_go", "conflicts", "staleness", "reopen"):
            value = conditions.get(field)
            if isinstance(value, list) and value:
                return True
    else:
        return True
    uncertainty = cert.get("uncertainty")
    if isinstance(uncertainty, dict):
        for field in ("unknown", "not_checked", "uncontrolled"):
            value = uncertainty.get(field)
            if isinstance(value, list) and value:
                return True
    else:
        return True
    lineage = cert.get("lineage")
    if isinstance(lineage, dict) and isinstance(lineage.get("dependencies"), list) and lineage["dependencies"]:
        return True
    if not isinstance(lineage, dict):
        return True
    validation_state = cert.get("validation_state")
    if isinstance(validation_state, dict):
        for field in ("structural", "referential", "closure", "artifact"):
            if validation_state.get(field) != "pass":
                return True
        if validation_state.get("semantic") != "not_performed":
            return True
    else:
        return True
    return False


def build_decision_envelope(
    cert: Any,
    projection: Any,
    producer_receipt: Any,
    *,
    task: Any,
    sources: Any,
    rubric: Any | None,
    artifact_root: str | Path | None = None,
    consumer_attempts: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    current = validate_certificate(cert, task=task, sources=sources, rubric=rubric, producer_receipt=producer_receipt, artifact_root=artifact_root, now=now)
    eq = verify_projection_equivalence(cert, projection)
    fallback = resolve_fallback(cert, sources, artifact_root=artifact_root)
    if (current["overall"] != "pass" or eq["status"] != "pass") and fallback["transition"] == "not_loaded":
        fallback = {**fallback, "transition": "load_full_material" if fallback["raw_source_available"] else "fail_closed_unavailable"}
    attempts_container_ok = consumer_attempts is None or isinstance(consumer_attempts, dict)
    attempts = consumer_attempts if isinstance(consumer_attempts, dict) else {}
    authority_ok = attempts_container_ok and attempts.get("authority", "advisory_only") == "advisory_only"
    source_ok = attempts_container_ok and _exact_bool_attempt(attempts, "source_available", True)
    baseline_ok = attempts_container_ok and _exact_bool_attempt(attempts, "baseline_execution_required", True)
    material_blocked = current["overall"] != "pass" or eq["status"] != "pass" or not fallback["raw_source_available"]
    policy_rejected = not authority_ok or not source_ok or not baseline_ok
    disposition = "accepted_advisory"
    if material_blocked:
        disposition = "failed_closed" if not fallback["raw_source_available"] else "reopened_full"
    elif policy_rejected:
        disposition = "rejected"
    bound_sources = []
    if current["overall"] == "pass" and isinstance(cert, dict) and isinstance(sources, dict):
        for binding in cert.get("source_bindings", []) if isinstance(cert.get("source_bindings"), list) else []:
            sid = binding.get("id") if isinstance(binding, dict) else None
            if isinstance(sid, str) and isinstance(sources.get(sid), dict):
                bound_sources.append({"id": sid, "version": sources[sid].get("version"), "digest": canonical_digest(sources[sid])})
    artifact_errors = current["checks"]["artifact"]["errors"]
    producer_receipt_available = not any("~1producer_receipt_ref" in item for item in artifact_errors)
    raw_source_available = fallback["raw_source_available"]
    envelope = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "canonical_profile": PROFILE_NAME,
        "projection_profile": CONSUMER_PROJECTION_PROFILE,
        "consumed": {
            "certificate": {"id": _safe_nullable_id(cert.get("certificate_id") if isinstance(cert, dict) else None), "digest": _safe_digest(cert)},
            "task": {"id": _safe_nullable_id(task.get("id") if isinstance(task, dict) else None), "digest": _safe_digest(task)},
            "sources": bound_sources,
            "rubric": None if rubric is None else {"id": _safe_nullable_id(rubric.get("id") if isinstance(rubric, dict) else None), "digest": _safe_digest(rubric)},
            "producer_receipt": {"id": _safe_nullable_id(producer_receipt.get("receipt_id") if isinstance(producer_receipt, dict) else None), "digest": _safe_digest(producer_receipt)},
        },
        "policy_checks": {
            "projection_equivalence": eq["status"],
            "current_validation": current["overall"],
            "consumer_authority_preserved": authority_ok,
            "source_override_refused": source_ok,
            "baseline_execution_required": True,
        },
        "included": projection.get("included") if current["overall"] == "pass" and eq["status"] == "pass" and isinstance(projection, dict) and isinstance(projection.get("included"), list) else [],
        "deferred": projection.get("deferred") if current["overall"] == "pass" and eq["status"] == "pass" and isinstance(projection, dict) and isinstance(projection.get("deferred"), list) else [],
        "producer_receipt_ref": _safe_producer_receipt_ref(cert, producer_receipt),
        "consumer_validation_receipt_ref": {"id": current["receipt_id"], "digest": canonical_digest(current)},
        "source_availability": {
            "producer_receipt_available": producer_receipt_available,
            "raw_source_available": raw_source_available,
            "complete_source_available": raw_source_available,
        },
        "fallback_result": fallback,
        "consumer_disposition": disposition,
        "no_final_judgment": True,
        "baseline_execution_required": True,
        "effects_applied": False,
    }
    return envelope


def _exact_bool_attempt(attempts: dict[str, Any], key: str, default: bool) -> bool:
    if key not in attempts:
        return default
    return attempts[key] if type(attempts[key]) is bool else False


def _safe_nullable_id(value: Any) -> str | None:
    return value if _id_ok(value) else None


def _safe_producer_receipt_ref(cert: Any, producer_receipt: Any) -> dict[str, str]:
    if isinstance(cert, dict) and isinstance(cert.get("producer_receipt_ref"), dict):
        ref = cert["producer_receipt_ref"]
        if _id_ok(ref.get("id")) and _digest_ok(ref.get("digest")):
            return {"id": ref["id"], "digest": ref["digest"]}
    if isinstance(producer_receipt, dict) and _id_ok(producer_receipt.get("receipt_id")):
        digest = _safe_digest(producer_receipt)
        if isinstance(digest, str):
            return {"id": producer_receipt["receipt_id"], "digest": digest}
    return {"id": "unavailable", "digest": "sha256:" + "0" * 64}
