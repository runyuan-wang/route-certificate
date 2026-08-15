# Contributing

RouteCertificate is an experimental reference implementation. Contributions should preserve its narrow authority and fail-closed mechanics.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src integrations tests
```

The runtime has no third-party dependencies. Optional schema validation tests may use an independently installed Draft 2020-12 validator, but no local module may shadow that package.

## Required invariants

A change must not:

- turn a certificate into a verdict, approval, score, recommendation, authorization, or mutation command;
- treat a digest, receipt, signature, or attestation as semantic truth;
- hide unavailable or mismatched raw source;
- weaken strict parsing, binding, projection-equivalence, containment, or fail-closed behavior;
- make a host adapter part of the portable core;
- claim quality, cost, security, portability, or production benefits without appropriate independent evidence.

Add deterministic regressions for changed behavior. Keep fixtures synthetic and relative-path-only. Do not commit credentials, private paths, transcripts, machine identifiers, generated caches, or vendored dependencies.

## Commit style

Prefer small commits with a clear behavioral rationale. By contributing, you agree that your contribution is licensed under Apache-2.0.
