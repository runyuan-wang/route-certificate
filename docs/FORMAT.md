# RouteCertificate v0 format and mechanics

This document describes the implemented v0 profile. JSON Schemas in `src/route_certificate/schemas/` are the machine-readable structural companion; `route_certificate.core` performs the current referential, closure, artifact, and policy checks.

## Canonical JSON profile

Profile identifier: `routecert-canonical-json-v0`.

The profile accepts JSON values only and enforces:

- UTF-8 input, valid Unicode, NFC strings, and no control characters;
- duplicate object-key rejection during parse;
- no floating-point or non-finite numbers;
- integers in `[-(2^53-1), 2^53-1]`;
- maximum document bytes 256 KiB, string bytes 4096, depth 16, nodes 10,000;
- bounded refusal of common secret-shaped values, private/internal path shapes, and prohibited verdict/approval/rejection/score/recommendation field names;
- UTF-8 serialization with sorted object keys, preserved array order, compact separators, and lowercase `sha256:` digests.

This is not RFC 8785/JCS. Canonical bytes are deterministic only inside the declared domain.

## Certificate

Schema version: `routecert.certificate.v0`.

Top-level fields are closed; unknown fields fail validation.

- `certificate_id`, `created_at`, `expires_at`: portable identity and strict UTC lifetime. Future or expired cards fail current validation.
- `producer`: role plus an identity reference. Authentication remains external.
- `authority`: must be `advisory_only`, must state that no final judgment is present, and must retain consumer responsibility.
- `task_binding`: exact `{id, version, digest}` of the supplied task descriptor.
- `source_bindings`: nonempty, unique exact bindings to every supplied source descriptor. Extra/unbound sources fail.
- `rubric_binding`: exact binding to the supplied rubric descriptor when present.
- `route`: ordered stages, risk order, and ordered heading/evidence inventory. These are navigation, not findings.
- `scope`: explicit in-scope and out-of-scope strings.
- `uncertainty`: separate `unknown`, `not_checked`, and `uncontrolled` arrays.
- `conditions`: separate `no_go`, `conflicts`, `staleness`, and `reopen` arrays. Any nonempty trigger requires full material.
- `fallback`: nonempty raw-source artifact references and explicit mismatch behavior.
- `validation_state`: structural/referential/closure/artifact must say `pass`; semantic must say `not_performed`. Current validation recomputes these mechanics rather than trusting the claim.
- `lineage`: conceptual lineage plus optional dependency edges. Nonempty dependencies require full material; cycles fail.
- `producer_receipt_ref`: exact ID/version/canonical digest plus contained relative path and byte digest.

## Binding digests

Descriptor bindings use the canonical digest of the parsed descriptor object:

```text
sha256(canonical_bytes(descriptor))
```

Artifact bindings use SHA-256 over the exact file bytes. These are distinct checks. Producer receipt validation additionally parses the bound artifact and requires its canonical object digest, ID, and version to match the supplied in-memory receipt.

## Current validation receipt

Schema version: `routecert.consumer-validation-receipt.v0`.

`validate_certificate` computes a new receipt with:

- an overall `pass` or `fail`;
- separate structural, referential, closure, artifact, and semantic layers;
- current subject digests;
- sanitized deterministic error codes/paths;
- an explicit semantic limit;
- a digest over the receipt body.

The producer receipt and current consumer validation receipt are separate. Neither receipt body is duplicated into the projection or decision envelope.

## Projection

Schema version: `routecert.projection.v0`.
Projection profile: `routecert-consumer-projection-v0`.

The named projection exposes all leaves under authority, bindings, route, scope, uncertainty, conditions, fallback, validation state, and producer-receipt reference. Every other leaf is listed under `deferred` with its canonical digest. Included and deferred pointer sets must be disjoint and exactly cover certificate leaves.

`build_projection(..., include_paths=...)` exists only as an unsafe compatibility helper. A consumer decision envelope rejects its `unsafe-caller-selected` profile.

## Raw fallback

Schema version: `routecert.raw-fallback.v0`.

Transitions:

- `not_loaded`: no trigger, and bound raw bytes are available;
- `load_full_material`: a trigger or current material failure requires verified raw bytes;
- `already_loaded`: caller declares an earlier complete load;
- `fail_closed_unavailable`: required raw bytes cannot be verified.

The resolver does not fetch data. It checks caller-provided local artifacts beneath one root and reports a transition.

## Consumer decision envelope

Schema version: `routecert.decision-envelope.v0`.

The envelope recomputes current validation and projection equivalence. It binds what was consumed, preserves source availability and fallback state, and records only `accepted_advisory`, `rejected`, `reopened_full`, or `failed_closed`. It never records a substantive verdict and never applies effects.

## Trust and time boundary

Validation is point-in-time. The core does not authenticate identities, sign receipts, lock files after reading, discover missing sources, or decide whether a task/rubric is substantively adequate. Those responsibilities remain with the consumer and host.
