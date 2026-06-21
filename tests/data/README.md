# apfs-forensic test data

Single repo-root `tests/data/` for both workspace members. Members reach fixtures
with a relative `include_bytes!("../../tests/data/<file>")` (never a symlink —
git on Windows materialises symlinks as text). Large images are **gitignored and
downloaded/minted manually**, env-gated in tests (skip cleanly when absent).

This README is the co-located human-facing detail; the single fleet machine-index
is [`issen/docs/corpus-catalog.md`](../../../issen/docs/corpus-catalog.md) —
cross-reference, never duplicate.

> **Status: planned.** No fixtures committed yet (parsers are stubs). Entries are
> added in the same change that introduces each fixture, per the fleet
> Test-Data Provenance Standard.

## Synthetic fixtures (mint commands)

Recorded here verbatim when added. Planned set (see `docs/validation.md`):

```sh
# Plain APFS container (GPT + APFS volume)
hdiutil create -size 64m -fs APFS -volname APFSTEST -layout GPTSPUD apfstest.dmg

# decmpfs-compressed files (macoS is the decode oracle)
#   attach apfstest.dmg, then:
ditto --hfsCompression /path/to/src /Volumes/APFSTEST/compressed

# Clones (shared extents)
cp -c bigfile /Volumes/APFSTEST/bigfile.clone

# Snapshots
tmutil localsnapshot     # or: diskutil apfs ...

# Encrypted volume
hdiutil create -size 64m -encryption -stdinpass -fs APFS -volname APFSENC apfsenc.dmg
```

## Real datasets (gitignored, env-gated)

Documented with Source / Identity / download URL / MD5 / contents /
redistribution when added (e.g. a real macOS Signed System Volume image for
Tier-1 sealed-volume validation). Consumed via an env var pointing at the path,
like the issen iOS corpus pattern.
