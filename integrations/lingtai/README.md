# LingTai reference integration

This directory is downstream of, and removable from, the generic core. Nothing under `src/route_certificate/` imports it.

## Status and exact lineage

The observer contract was tested in LingTai at exact source commit:

`9bb869c4fd101ae1247db0e6b7839138f06abbe7`

That commit's focused implementation covered the real automatic terminal-notification seam. The small module here is a framework-facing **reference contract**, not a vendored copy of the LingTai kernel patch and not a drop-in installer. It deliberately contains no runtime paths, daemon transcripts, machine identities, configuration, credentials, or activation logic.

## Boundaries

`return_observer_adapter.py` demonstrates these invariants:

1. default off; disabled mode does not call the observer;
2. terminal truth and raw result bytes already exist before observation;
3. success adds one validated advisory notice to a copy of the ordinary notification;
4. observer exceptions or malformed output leave raw bytes and ordinary notification unchanged;
5. the adapter cannot reorder or alter terminal truth, ordinary result retrieval, or final consumer authority.

The full tested LingTai implementation used a bounded helper process and local sidecar receipts. Hashes/receipts bind bytes and provenance; they do not prove semantic truth, security, quality, or authorization. Direct file reads and unrelated consumption paths are outside this automatic-notification observer seam.

`shadow_adapter.py` separately demonstrates host-ID/source-descriptor mapping into generic bindings. It remains advisory, keeps baseline execution required, applies no effects, and emits sanitized failure codes.

Run the repository tests to verify both adapters:

```bash
python -m unittest discover -s tests -v
```
