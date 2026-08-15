# RouteCertificate

RouteCertificate is a portable, source-bound, **advisory** navigation artifact for evidence-heavy review and decision work. It records what task is being performed, which exact source/rubric material is bound, what route and risks should be inspected, what remains unknown, and when the consumer must reopen complete raw material.

It does **not** provide the final judgment.

> **Status:** `0.1.0` experimental reference implementation. The deterministic Python core and synthetic fixtures are runnable; broad portability, production fitness, security, general quality gain, and cost benefit are not established.

## Why a separate certificate?

A compact route can help a reviewer find consequential material, but a route becomes dangerous when it silently replaces evidence or impersonates a verdict. RouteCertificate separates five things:

1. the canonical certificate produced upstream;
2. exact task/source/rubric and receipt bindings;
3. a deterministic consumer-facing projection with explicit included/deferred fields;
4. current consumer validation and raw-source fallback;
5. the consumer-owned decision envelope and final substantive judgment.

The certificate remains a navigation card. The complete source remains authoritative.

## Mechanical guarantees

The standard-library core implements:

- strict bounded JSON input (duplicate-key rejection, no floats/non-finite values, safe integers, NFC Unicode, size/depth/node caps);
- deterministic `routecert-canonical-json-v0` bytes and SHA-256 digests;
- exact task, source, rubric, producer-receipt, and artifact bindings;
- distinct uncertainty, not-checked, uncontrolled, no-go, conflict, staleness, and reopen fields;
- an advisory-only authority boundary that refuses verdict/approval/score/recommendation fields;
- a named projection with complete included/deferred leaf coverage and RFC 6901 pointers;
- current consumer validation, separate from producer claims;
- contained relative artifact resolution, symlink refusal, and byte-digest checks;
- mandatory raw/full-source fallback and fail-closed certificate validity;
- a consumer decision envelope that applies no effects and preserves final consumer authority.

These mechanics establish identity, integrity, and provenance **binding**. They do not establish semantic truth, relevance, quality, safety, security, authorization, or producer trust.

## Quick start

Requires Python 3.10 or later. The runtime has no third-party dependencies.

```bash
git clone https://github.com/runyuan-wang/route-certificate.git
cd route-certificate
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

Validate the synthetic example at its frozen test time:

```bash
route-certificate validate \
  --certificate examples/certificate.json \
  --task examples/task.json \
  --sources examples/sources.json \
  --rubric examples/rubric.json \
  --producer-receipt examples/receipts/producer-receipt-001.json \
  --artifact-root examples \
  --now 2026-08-13T12:00:00Z
```

A passing receipt still says semantic validation was not performed.

Build and verify the named projection:

```bash
route-certificate project \
  --certificate examples/certificate.json > /tmp/routecert-projection.json

route-certificate verify-projection \
  --certificate examples/certificate.json \
  --projection /tmp/routecert-projection.json
```

Build the consumer envelope:

```bash
route-certificate envelope \
  --certificate examples/certificate.json \
  --projection /tmp/routecert-projection.json \
  --task examples/task.json \
  --sources examples/sources.json \
  --rubric examples/rubric.json \
  --producer-receipt examples/receipts/producer-receipt-001.json \
  --artifact-root examples \
  --now 2026-08-13T12:00:00Z
```

Other commands:

```bash
route-certificate digest examples/certificate.json
route-certificate canonicalize examples/certificate.json
python -m route_certificate --version
```

CLI exit codes are `0` for the command's passing/accepted-advisory state, `1` for a mechanically valid fail/reopen/reject state, and `2` for invalid or unavailable input. Error output deliberately avoids echoing filenames or hostile input values.

## Python API

```python
from pathlib import Path
from route_certificate import (
    build_decision_envelope,
    build_profile_projection,
    load_json_strict,
    validate_certificate,
)

root = Path("examples")
cert = load_json_strict((root / "certificate.json").read_bytes())
task = load_json_strict((root / "task.json").read_bytes())
sources = load_json_strict((root / "sources.json").read_bytes())
rubric = load_json_strict((root / "rubric.json").read_bytes())
producer = load_json_strict((root / "receipts/producer-receipt-001.json").read_bytes())

receipt = validate_certificate(
    cert,
    task=task,
    sources=sources,
    rubric=rubric,
    producer_receipt=producer,
    artifact_root=root,
    now="2026-08-13T12:00:00Z",
)
projection = build_profile_projection(cert)
envelope = build_decision_envelope(
    cert,
    projection,
    producer,
    task=task,
    sources=sources,
    rubric=rubric,
    artifact_root=root,
    now="2026-08-13T12:00:00Z",
)
```

## Consumer behavior

The decision envelope uses only these dispositions:

| Disposition | Meaning |
|---|---|
| `accepted_advisory` | Current mechanical checks pass; the route may be consumed as advice. |
| `rejected` | Consumer policy/authority requirements reject the card; no claim that raw material was loaded. |
| `reopened_full` | Certificate/projection material failed, but verified raw material is available and must be reopened. |
| `failed_closed` | Required raw material cannot be verified; the certificate cannot be used. |

Every envelope keeps `no_final_judgment=true`, `baseline_execution_required=true`, and `effects_applied=false`.

## Canonicalization profile

`routecert-canonical-json-v0` is intentionally named and versioned. It is **not RFC 8785/JCS**. It serializes strict JSON as UTF-8 with recursively sorted object keys and compact separators after enforcing the bounded domain documented in [`docs/FORMAT.md`](docs/FORMAT.md). Another language must pass independent cross-language vectors before claiming profile compatibility.

## Schemas and examples

Draft 2020-12 schemas are bundled in `src/route_certificate/schemas/`. Runtime checks remain explicit and standard-library-only; the schemas are interoperable contract documents rather than a hidden runtime dependency.

The `examples/` packet is synthetic and fully relative. It contains:

- certificate, task, source mapping, and rubric descriptors;
- the bound producer receipt;
- the exact raw-source fallback bytes.

## Thin integrations

The generic core imports no LingTai code and knows nothing about daemon IDs, lifecycle state, provider APIs, prompts, or channels.

[`integrations/lingtai/`](integrations/lingtai/) contains two removable examples:

- sanitized host-input mapping into portable bindings;
- a default-off, additive-only, raw-first return-observer seam that fails open to ordinary raw delivery.

The observer contract is labelled against exact tested LingTai source commit `9bb869c4fd101ae1247db0e6b7839138f06abbe7`. This repository does not vendor the kernel patch, activate a runtime, or change ordinary result retrieval.

## Evidence and maturity

Deterministic predecessor implementations passed extensive local hostile-input, projection, artifact, fault-injection, and observer tests. That evidence supports the bounded mechanics, not broad product claims.

One genuine paired smoke improved decision quality on one task while increasing cache-miss input by **27,375 tokens (9.84%)**. This n=1 observation does not establish a general quality gain or an efficiency benefit. Fresh, independent, quality-first testing must precede any optimization claim; token savings can never compensate for a material quality regression.

See [`LIMITATIONS.md`](LIMITATIONS.md) for the complete evidence boundary and [`SECURITY.md`](SECURITY.md) for the threat boundary.

## Project layout

```text
src/route_certificate/       generic core, CLI, bundled schemas
examples/                    synthetic complete packet and raw fallback
integrations/lingtai/        removable downstream reference integration
tests/                       deterministic standard-library tests
docs/FORMAT.md               normative v0 mechanics and field guide
PROJECT.json                 machine-readable project/profile manifest
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
