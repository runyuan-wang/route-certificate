# Security policy

## Status

This project is an experimental reference implementation, not a security product or production authorization system. It has no cryptographic signing, key management, sandbox, network policy, or complete secret detector.

## Reporting

Please use GitHub's private security-advisory reporting feature for vulnerabilities when available. Do not place credentials, private source material, exploit secrets, or machine-identifying paths in a public issue.

## Security boundary

The core performs bounded strict parsing, common secret/path-shape refusal, relative-path containment, symlink refusal, byte hashing, and fail-closed current validation. These are defense-in-depth mechanics, not proof that input is safe, true, complete, or authorized.

Consumers remain responsible for:

- authenticating producers and transport;
- deciding which digests and identities they trust;
- protecting raw source and receipts at rest and in transit;
- applying OS-level sandboxing, permissions, and network controls;
- independently evaluating semantic truth and authorization;
- keeping the complete raw source available when the certificate is invalid or insufficient.

See `LIMITATIONS.md` for known gaps.
