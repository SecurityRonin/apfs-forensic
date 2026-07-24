# apfs-forensic — Purpose & Scope

This is a **library** design/intent doc, not a PRD: `apfs-forensic` ships no
examiner-run binary. It is two published Rust library crates that other fleet
tools (Issen orchestration, `disk4n6`, a future GUI) link. For the decision
record behind the choices summarized here, see [`decisions/`](decisions/); for
the full multi-week build research, see
[`plans/2026-06-21-apfs-forensic-design.md`](plans/2026-06-21-apfs-forensic-design.md).

## Problem

macOS evidence lives on APFS, a copy-on-write, transactional, object-oriented
filesystem. A "clean" read-only mount of an APFS volume presents the *live*
state and hides exactly what a forensic examiner needs: superseded objects that
survive in older checkpoints and unreaped space until overwritten, snapshot and
checkpoint-ring tampering, sealed/signed-system-volume integrity state,
object-map inconsistencies, clone/dedup provenance, and encryption state. No
maintained, forensic-grade Rust APFS reader existed on crates.io (ADR 0001), so
the fleet had no way to navigate or audit APFS evidence in pure Rust.

## Who uses it

Rust developers and DFIR tooling, not end-user analysts directly:

- `apfs-core` — any Rust tool that needs to read APFS over a `Read + Seek`
  source (extract files, walk the tree, read snapshots, decompress decmpfs), or
  compose an APFS volume/snapshot into the fleet VFS via the optional `vfs`
  feature (ADR 0006).
- `apfs-forensic` — orchestration layers that aggregate graded APFS anomaly
  findings into a `forensicnomicon::report::Report` alongside partition- and
  container-layer findings (ADR 0005).

## What it does

- **`apfs-core` (the reader):** NXSB container open + checkpoint ring, object
  map, B-trees, APSB volume superblocks, file-system records (`j_key`),
  inode/directory navigation, file extents, extended attributes, snapshots with
  point-in-time views, the space manager (allocation bitmap) + reaper, keybag
  and sealed-volume (integrity-meta) metadata, and transparent decmpfs
  decompression (DEFLATE/LZVN/LZFSE via reused pure-Rust codecs, ADR 0004).
  Navigation is `container → checkpoint → live NXSB → omap → APSB → fs-tree →
  j_key → INODE → FILE_EXTENT → bytes → (decmpfs?) → content` — the APFS
  analogue of NTFS `name → inode → runs → bytes`.
- **`apfs-forensic` (the auditor):** a typed `AnomalyKind` enum + `audit_container`
  / `audit_volume` entry points that convert each anomaly into a graded,
  scheme-prefixed `forensicnomicon::report::Finding` (e.g.
  `APFS-SEALED-VOLUME-BROKEN`, `APFS-XID-REUSE`, `APFS-SNAPSHOT-XID-DISORDER`,
  `APFS-REAPER-PENDING-OBJECT`, `APFS-ENCRYPTION-STATE`). Findings are
  observations ("consistent with …"), never verdicts.

## Scope

- Read-only navigation and anomaly auditing of APFS containers, volumes, and
  snapshots over an in-memory or on-disk byte source.
- The forensic differentiators above: snapshot/checkpoint tampering, sealed-
  volume integrity, recoverable deleted records, object-map inconsistency,
  clone/dedup and encryption-state surfacing.

## Non-goals

- **No writing to evidence.** Both the byte source and (via `forensic-vfs`) the
  filesystem contract are read-only.
- **No end-user binary.** The examiner-facing CLI is `disk4n6`/Issen; this repo
  is linked, not run. A `cli/` debug member is not part of the shipped surface.
- **No key derivation / decryption.** The reader *surfaces* encryption and
  keybag state (raw tags, offsets) but does not unwrap keys or decrypt content.
- **No unsupported device tiers, silently.** Fusion address translation and the
  space-manager CAB indirection tier are rejected loudly at `open()` rather than
  best-effort mis-read (ADR 0007), pending validating fixtures.
- **No C bindings / no `unsafe`.** `unsafe_code = "forbid"` (ADR 0008); the
  LGPL/GPL/AGPL APFS references (libfsapfs, apfs-fuse, apfsprogs, dissect.apfs)
  are external oracles run as separate binaries, never linked.

## Artifact family

Apple File System (APFS) — the on-disk container/volume format used by macOS,
iOS, iPadOS, tvOS, and watchOS, including snapshots (Time Machine local
snapshots), sealed/signed system volumes, FileVault-encrypted volumes, and
clonefile/dedup structures.

## Validation approach

Correctness is proven against independent oracles, not self-authored fixtures
alone (see [`validation.md`](validation.md)). Oracles: macOS's own driver
(`hdiutil attach -readonly`, `diskutil apfs`, `stat`, `xattr`), The Sleuth Kit
`fsstat`/`fls`/`istat` (v4.12.1), `fsapfsinfo` (libfsapfs), `apfsck`
(apfsprogs), apfs-fuse, and the `apfs`/`exhume_apfs` crates for spot
cross-checks. A decmpfs file read via `apfs-core::extent::read_data` must be
SHA-256-identical to a macOS `cp` of the same file. Corpora are minted on a
macOS host (`hdiutil create -fs APFS`, `tmutil localsnapshot`, `cp -c`,
`ditto --hfsCompression`) with real SSV/macOS images env-gated for Tier-1
claims. Evidence is tiered explicitly: `min(oracle independence, corpus
provenance)`. The panic-free posture (ADR 0008) is exercised by one cargo-fuzz
target per parsed structure plus a full-pipeline target.
