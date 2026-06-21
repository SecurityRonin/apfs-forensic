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

## Validated capabilities

### Object map + B-tree navigation + volume-superblock resolution (P2) — Tier 2

**Corpus:** `tests/data/apfs_container_chain.bin` — blocks 0–344 (1.38 MiB) of a
real APFS *container partition* minted by Apple's own `hdiutil`
(`hdiutil create -size 128m -fs APFS -volname APFSORACLE -layout GPTSPUD`). The
slice holds the complete checkpoint ring **and** the full
NXSB → container omap → omap B-tree → volume superblock (APSB) chain. Because the
carve starts at NXSB block 0, a physical block address maps directly to
`paddr * 4096` in the fixture. Provenance + MD5 in `tests/data/README.md`.

**What is exercised** (`core/tests/{omap,btree,btree_descend,volume_resolve}.rs`):

| Claim | Evidence | Oracle |
|---|---|---|
| `omap_phys_t` header decode (`om_flags`/`om_tree_type`/`om_tree_oid`/`om_snapshot_tree_oid`) | `nx_omap_oid = 343` → `om_tree_oid = 344`, `om_flags = OMAP_MANUALLY_MANAGED` | offsets verified verbatim vs the Apple reference + libfsapfs; raw-image decode |
| `btree_node_phys_t` header + TOC iterate (fixed + variable KV) | omap root @344: `btn_flags = 0x7` (ROOT\|LEAF\|FIXED), 1 fixed entry `omap_key(1026,2)` → `omap_val(paddr 342)` | Apple reference + libfsapfs spec (4-byte `kvoff_t`, 8-byte `kvloc_t`, `btree_info` footer) |
| Root→leaf descent with cksum + cycle guards | real omap walk yields exactly `(1026, 2, 342)`; a corrupted node fails Fletcher-64 (`ChecksumMismatch`); a self-referential index node trips `CycleGuard` | construction; checksum-before-trust |
| Virtual `nx_fs_oid` → physical APSB paddr | `volume_superblock_addrs() == [342]`; block 342 carries APSB magic `0x42535041` + valid Fletcher-64 | **Apple `diskutil apfs list`** and **libfsapfs `fsapfsinfo`** (run on the committed fixture) each report **exactly one volume** (`APFSORACLE`) — matching the single resolved APSB |

**Independence:** `fsapfsinfo` (libfsapfs, a separate C codebase) reads the exact
committed `apfs_container_chain.bin` and reports `Number of volumes: 1`, volume
identifier `fa8b74aa-…`, name `APFSORACLE` — matching Apple `diskutil`. The
B-tree TOC and value offsets were verified verbatim against the Apple *APFS
Reference* and the libfsapfs format spec before implementation, not from memory.

**Tier rationale:** independent oracle (libfsapfs/diskutil) on a **self-minted**
corpus ⇒ Tier 2 (`min(independent, self-minted)`). A Tier-1 lift needs the same
resolution run on a real-world / third-party image (env-gated, future work).
