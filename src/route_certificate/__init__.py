"""Portable source-bound advisory RouteCertificate core."""

from .core import (
    CERT_SCHEMA_VERSION,
    CONSUMER_PROJECTION_PROFILE,
    ENVELOPE_SCHEMA_VERSION,
    PROFILE_NAME,
    RECEIPT_SCHEMA_VERSION,
    RouteCertError,
    build_decision_envelope,
    build_profile_projection,
    build_projection,
    canonical_bytes,
    canonical_digest,
    is_valid_id,
    load_json_strict,
    resolve_fallback,
    validate_certificate,
    validate_json_value,
    verify_projection_equivalence,
)

__version__ = "0.1.0"

__all__ = [
    "CERT_SCHEMA_VERSION",
    "CONSUMER_PROJECTION_PROFILE",
    "ENVELOPE_SCHEMA_VERSION",
    "PROFILE_NAME",
    "RECEIPT_SCHEMA_VERSION",
    "RouteCertError",
    "__version__",
    "build_decision_envelope",
    "build_profile_projection",
    "build_projection",
    "canonical_bytes",
    "canonical_digest",
    "is_valid_id",
    "load_json_strict",
    "resolve_fallback",
    "validate_certificate",
    "validate_json_value",
    "verify_projection_equivalence",
]
