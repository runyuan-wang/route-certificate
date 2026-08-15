# Limitations and evidence boundary

RouteCertificate 0.1.0 is an experimental reference implementation.

## What is mechanically supported

- bounded strict JSON parsing and a named deterministic canonicalization profile;
- task, source, rubric, producer-receipt, and artifact digest binding;
- advisory-only authority and explicit uncertainty/no-go/reopen representation;
- deterministic consumer projection with included/deferred leaf coverage;
- current consumer validation and a separate decision envelope;
- verified raw-source fallback references and fail-closed invalidity;
- removable host adapters, including a bounded LingTai reference seam.

## What is not established

- semantic truth, relevance, quality, safety, security, authorization, or producer trust;
- complete dependency graphs, peer discovery, source discovery, or provenance completeness;
- complete secret/path detection or adversarial filesystem safety on every platform;
- general portability across languages, operating systems, runtimes, providers, or agent frameworks;
- production readiness, stable v1 compatibility, causal gain, or broad user benefit;
- a general quality or efficiency advantage.

One genuine paired smoke improved decision quality on that single task while increasing cache-miss input by **27,375 tokens (9.84%)**. This n=1 observation proves neither a general quality gain nor a cost benefit. Quality-first testing on fresh tasks must precede any efficiency claim.

## Canonicalization

`routecert-canonical-json-v0` is a project-specific profile, not RFC 8785/JCS. It rejects floating-point numbers, restricts integers to the interoperable `±(2^53-1)` range, requires NFC strings, rejects duplicate keys and controls, and serializes UTF-8 JSON with recursively sorted object keys and compact separators. Cross-language compatibility is unproved and must be validated with independent test vectors before another implementation claims conformance.

## Temporal and filesystem behavior

Validation uses current UTC by default and accepts an explicit UTC time for reproducible tests. Certificates created in the future, expired certificates, malformed timestamps, unresolved artifacts, symlinks, path traversal, and digest mismatches fail current validation. Files can still change after validation; a receipt is a point-in-time observation, not an enduring lock.

## Adapter boundary

Adapters may map host identifiers, collect bounded telemetry, or add advisory observation references. They must not alter terminal truth, ordinary raw delivery, core authority, fallback requirements, or consumer responsibility. The LingTai example covers the automatic terminal-notification seam only; it does not certify arbitrary direct file reads or every result-consumption path.
