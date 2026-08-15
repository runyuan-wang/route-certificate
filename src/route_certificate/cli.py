"""Command-line interface for deterministic RouteCertificate mechanics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .core import (
    RouteCertError,
    build_decision_envelope,
    build_profile_projection,
    canonical_bytes,
    canonical_digest,
    load_json_strict,
    validate_certificate,
    verify_projection_equivalence,
)


def _load(path: str) -> Any:
    return load_json_strict(Path(path).read_bytes())


def _emit(value: Any) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def _common_material(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--sources", required=True, help="JSON object mapping source IDs to descriptors")
    parser.add_argument("--rubric", help="rubric JSON; omit only when the certificate has no rubric binding")
    parser.add_argument("--producer-receipt", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--now", help="deterministic UTC validation time, e.g. 2026-08-13T12:00:00Z")


def _material(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "cert": _load(args.certificate),
        "task": _load(args.task),
        "sources": _load(args.sources),
        "rubric": None if args.rubric is None else _load(args.rubric),
        "producer_receipt": _load(args.producer_receipt),
        "artifact_root": args.artifact_root,
        "now": args.now,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="route-certificate",
        description="Validate and consume source-bound advisory RouteCertificates.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    digest = commands.add_parser("digest", help="print the canonical SHA-256 digest of strict JSON")
    digest.add_argument("document")

    canonicalize = commands.add_parser("canonicalize", help="write canonical profile bytes")
    canonicalize.add_argument("document")

    project = commands.add_parser("project", help="build the named safe consumer projection")
    project.add_argument("--certificate", required=True)

    verify = commands.add_parser("verify-projection", help="verify projection coverage and binding")
    verify.add_argument("--certificate", required=True)
    verify.add_argument("--projection", required=True)

    validate = commands.add_parser("validate", help="perform current fail-closed mechanical validation")
    _common_material(validate)

    envelope = commands.add_parser("envelope", help="build a consumer decision envelope")
    _common_material(envelope)
    envelope.add_argument("--projection", required=True)
    envelope.add_argument("--consumer-attempts", help="optional JSON policy-attempt object")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "digest":
            sys.stdout.write(canonical_digest(_load(args.document)) + "\n")
            return 0
        if args.command == "canonicalize":
            sys.stdout.buffer.write(canonical_bytes(_load(args.document)) + b"\n")
            return 0
        if args.command == "project":
            _emit(build_profile_projection(_load(args.certificate)))
            return 0
        if args.command == "verify-projection":
            result = verify_projection_equivalence(_load(args.certificate), _load(args.projection))
            _emit(result)
            return 0 if result["status"] == "pass" else 1
        if args.command == "validate":
            values = _material(args)
            receipt = validate_certificate(
                values["cert"],
                task=values["task"],
                sources=values["sources"],
                rubric=values["rubric"],
                producer_receipt=values["producer_receipt"],
                artifact_root=values["artifact_root"],
                now=values["now"],
            )
            _emit(receipt)
            return 0 if receipt["overall"] == "pass" else 1
        if args.command == "envelope":
            values = _material(args)
            attempts = None if args.consumer_attempts is None else _load(args.consumer_attempts)
            result = build_decision_envelope(
                values["cert"],
                _load(args.projection),
                values["producer_receipt"],
                task=values["task"],
                sources=values["sources"],
                rubric=values["rubric"],
                artifact_root=values["artifact_root"],
                consumer_attempts=attempts,
                now=values["now"],
            )
            _emit(result)
            return 0 if result["consumer_disposition"] == "accepted_advisory" else 1
    except (OSError, RouteCertError, TypeError, ValueError, KeyError):
        _emit({"status": "error", "error": "invalid_or_unavailable_input", "effects_applied": False})
        return 2
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
