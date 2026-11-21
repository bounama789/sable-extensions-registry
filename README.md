# Sable Extension Registry

Neutral catalog for Sable IDE extensions. The registry knows no publisher's
private key. Publishers submit self-contained entries by PR; the registry
verifies them and signs only the aggregated catalog.

## For publishers

1. Put your extension files at the root of your own git repo.
2. Commit them; note the commit SHA (immutable pin).
3. With YOUR publisher private key, build an entry:
   `SABLE_PUB_KEY=your.pem python3 tools/make-entry.py ...`
4. Open a PR adding `entries/<id>.json`. CI verifies the digest, signature,
   permissions, and identity law before merge.

## For the registry operator

One CI secret: `SABLE_ROOT_KEY` (signs the catalog). On merge, `build-catalog.py`
assembles `catalog.json` from `entries/`, signs it, commits it, and Pages serves
it at `https://bounama789.github.io/sable-extensions-registry/catalog.json`.

## Verification law

`store_law.py` is the Python half; the app's `ext-store` module is the Kotlin
half. `conformance/vectors.json` is shared by both. If they disagree, CI fails.

NOTE: `entries/sable.lang-python.json` is a sample with a placeholder ref.
Replace it with a real repo SHA and matching digest before it is trusted.
