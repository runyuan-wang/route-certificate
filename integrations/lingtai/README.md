# LingTai reference integration

This directory is downstream of, and removable from, the generic core. Nothing under `src/route_certificate/` imports it.

## Status and exact lineage

The observer contract was tested in LingTai at exact source commit:

`2f3d885b5c2200fbad07420336ad60f0c61a800c`

That commit's focused implementation covered the real automatic terminal-notification seam. The small module here is a framework-facing **reference contract**, not a vendored copy of the LingTai kernel patch and not a drop-in installer. It deliberately contains no runtime paths, daemon transcripts, machine identities, configuration, credentials, or activation logic.

## Boundaries

`return_observer_adapter.py` demonstrates these invariants:

1. default off; disabled mode does not call the observer;
2. terminal truth and raw result bytes already exist before observation;
3. success adds one validated advisory notice to a copy of the ordinary notification;
4. observer exceptions or malformed output leave raw bytes and ordinary notification unchanged;
5. the adapter cannot reorder or alter terminal truth, ordinary result retrieval, or final consumer authority.

The full tested LingTai implementation used a bounded helper process and local sidecar receipts. Hashes/receipts bind bytes and provenance; they do not prove semantic truth, security, quality, or authorization. Direct file reads and unrelated consumption paths are outside this automatic-notification observer seam.

## Oversized advisory artifacts: sanitized real-use case

[`fixtures/oversized-artifact-observation-case.v0.json`](fixtures/oversized-artifact-observation-case.v0.json) records a bounded, content-free case tied to the public PR head above and to reviewed correction diff SHA-256 `4d695d244e7972d312ef5e7b1631126183f7edfbe567f27aaea8d015e5172fa3`. The diff binding is explicit because this reference must not invent a future LingTai commit ID.

Two genuine same-batch concurrent returns invoked the helper successfully (exit 0 with empty stderr), but each declared transcript and event-log artifact exceeded the unchanged 262,144-byte per-file observation cap. Ordinary raw terminal delivery remained correct while the additive `g0000` generation was absent. The reviewed correction keeps the cap and makes this optional advisory layer use metadata-only omission for oversized or over-total-budget artifacts: the portable difference record retains relative reference, reason, observed size and cap, plus any declared-versus-observed size mismatch, while the omitted file is not read or listed as content-observed and receives no content-digest claim.

The final local gates were 71 focused observer tests, one parent metadata-mismatch probe, 12 adjacent terminal tests, three copied real fixtures and nine portable receipts; `g0000` was restored for all three copied fixtures. Raw results, terminal state and exactly-one logical terminal notification remained unchanged.

This omission rule is deliberately narrower than RouteCertificate raw-source validation. Required authoritative raw fallback remains fail-closed when its bytes cannot be verified; an implementation must not use advisory omission metadata as a substitute for required source material. The case is reliability evidence for the optional observer seam, not evidence of semantic truth, optimization benefit, general quality gain, security, authorization or production fitness.

`shadow_adapter.py` separately demonstrates host-ID/source-descriptor mapping into generic bindings. It remains advisory, keeps baseline execution required, applies no effects, and emits sanitized failure codes.

Run the repository tests to verify both adapters and the sanitized case fixture:

```bash
python -m unittest discover -s tests -v
```
