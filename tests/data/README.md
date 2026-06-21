# apfs-forensic test data

Single repo-root `tests/data/` for both workspace members. Members reach fixtures
with a relative `include_bytes!("../../tests/data/<file>")` (never a symlink —
git on Windows materialises symlinks as text). Large images are **gitignored and
downloaded/minted manually**, env-gated in tests (skip cleanly when absent).

This README is the co-located human-facing detail; the single fleet machine-index
is [`issen/docs/corpus-catalog.md`](../../../issen/docs/corpus-catalog.md) —
cross-reference, never duplicate.

## Committed fixtures

#### `apfs_nxsb_head.bin`

- **Class:** SYNTHETIC (self-minted real APFS), Tier 2.
- **What it is:** the first 17 blocks (68 KiB, 4096-byte blocks) of a real APFS
  *container partition* — block 0 (a copy of the live container superblock),
  the checkpoint **descriptor area** (blocks 1–8: alternating
  `checkpoint_map_phys_t` + `nx_superblock_t`), and the head of the checkpoint
  **data area** (blocks 9+: spaceman, reaper, btree objects). Holds a complete,
  verifiable checkpoint ring.
- **Source:** minted on this macOS host by Apple's own `hdiutil`, so every
  on-disk structure (incl. the stored Fletcher-64 checksums) is Apple-authored.
- **Verbatim mint + carve commands:**
  ```sh
  # 1. Mint a 128 MiB GPT+APFS container image (Apple driver authors it)
  hdiutil create -size 128m -fs APFS -volname APFSORACLE -layout GPTSPUD /tmp/apfs_oracle
  # 2. Attach without mounting; the APFS container sits on a GPT partition
  hdiutil attach -nomount /tmp/apfs_oracle.dmg          # -> /dev/diskN, partition diskNs1
  # 3. Carve the first 17 blocks of the container partition (Apple_APFS slice)
  dd if=/dev/diskNs1 of=apfs_nxsb_head.bin bs=4096 count=17
  ```
  (`mmls` shows the Apple_APFS partition starts at sector 40 = byte 20480 of the
  whole `.dmg`; reading `/dev/diskNs1` addresses the partition directly so the
  carve starts at NXSB block 0.)
- **MD5:** `81505414be7754a3927091574aaea5a4`
- **Container UUID (cross-checked):** `40115033-9523-4496-96A2-0EDADEECA565`
  — echoed verbatim by `diskutil info /dev/diskN` (`Disk / Partition UUID`).
- **Independent oracles:** Apple `hdiutil`/`diskutil` (block size 4096, container
  UUID); the *documented construction* (magic `NXSB`, 4096-byte blocks); the
  stored Fletcher-64 checksum of every object recomputes to its `o_cksum`.
- **Redistribution:** entirely machine-generated empty container; no third-party
  or personal content. Safe to commit.
- **Consumed by:** `core/tests/object.rs` (obj_phys + Fletcher-64),
  `core/tests/container.rs` (NXSB geometry), `core/tests/checkpoint.rs`
  (checkpoint-ring walk to the live superblock).

## Synthetic fixtures (other mint commands)

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
