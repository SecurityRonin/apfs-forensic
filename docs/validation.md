# Validation

> **Status: planned.** This document specifies the validation strategy; results
> are recorded here as each phase lands. No correctness is claimed yet.

## How to read the evidence tiers

- **Tier 1** — an independent third party authored both the artifact and the
  answer key, or the data is real-world.
- **Tier 2** — real engine/tool output whose ground truth is derivable from the
  documented construction or confirmed by an independent oracle, but we chose the
  scenario (so it can miss real-world quirks).
- **Tier 3** — we authored both the fixture and the expected answer with nothing
  independent vouching (maximal self-deception risk; labelled, never read as
  Tier 1).

**Oracle independence and corpus tier are orthogonal.** The tier of a claim is
`min(oracle independence, corpus provenance)`: an independent oracle run against a
corpus we minted ourselves is **Tier 2**; only an independent oracle on real-world
data reaches **Tier 1**.

## Independent oracles

| Oracle | Independence | Validates | Install |
|---|---|---|---|
| **macOS** (`hdiutil attach -readonly`, `diskutil apfs list`, `stat`, `xattr`, `ls -lR@`) | Apple's own driver | directory tree, file bytes (post-decmpfs), timestamps, xattrs, snapshots | present |
| **The Sleuth Kit** `fsstat`/`fls`/`istat` (v4.12.1) | separate C codebase | container/volume geometry, inode listing + metadata | installed |
| **`fsapfsinfo`** (libfsapfs) | independent | NXSB/APSB fields, volumes, btree/omap, snapshots | build (LGPL — oracle only) |
| **`apfsck`** (apfsprogs) | structural fsck | checksum/omap/btree/spaceman structural integrity | build |
| **apfs-fuse** | independent | decmpfs decode + encrypted-volume unwrap | build (GPL — oracle only) |
| **`apfs` / `exhume_apfs` crates** | independent Rust | spot field cross-check | crates.io |

Cross-extractor check: macOS `cp` of a decmpfs file vs `apfs-core::extent::read_data`
must be byte-identical (same SHA-256), so neither extractor's assumptions are
load-bearing alone.

## Corpora (mintable on a macOS host)

| Corpus | Mint command | Tier |
|---|---|---|
| Plain APFS | `hdiutil create -size 64m -fs APFS -volname APFSTEST -layout GPTSPUD apfstest.dmg` | 2 |
| Snapshots | attach → `tmutil localsnapshot` / `diskutil apfs` → detach | 2 |
| decmpfs | `ditto --hfsCompression src dst` on the attached volume | 2 (macOS oracle) |
| Clones | `cp -c` (clonefile) on the attached volume | 2 |
| Encrypted | `hdiutil create -encryption -stdinpass -fs APFS …` | 2 |
| Sealed system volume | real macOS SSV image (env-gated, gitignored) | 1 |
| Real macOS images | env-gated, gitignored | 1 |

Verbatim mint commands are recorded in `issen/docs/corpus-catalog.md` and
`tests/data/README.md`. Carving/recovery is validated against an **independent**
oracle (real images / pre-delete capture + apfsck), not only records we deleted
ourselves.
