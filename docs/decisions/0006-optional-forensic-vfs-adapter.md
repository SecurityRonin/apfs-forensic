# 6. Adapt `ApfsFs` to `forensic-vfs` behind an optional `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet's VFS policy (`ronin-issen/CLAUDE.md` — "VFS & Universal Container
Abstraction") says a filesystem reader should implement the `forensic-vfs`
`FileSystem` contract so a whole stack (`E01 → GPT → BitLocker → NTFS`, or here
an APFS volume/snapshot) composes as one `Arc<dyn ImageSource>`/`Arc<dyn
FileSystem>` that many workers share and no path can write. But a bare reader
should stay dependency-light for third-party consumers that only want to parse
APFS, so the adapter must not be unconditional. `ntfs-core` sets the precedent
with its own optional `vfs` feature.

## Decision

Gate the `impl FileSystem for ApfsFs` adapter (`core/src/vfs.rs`) behind an
optional `vfs` Cargo feature: `forensic-vfs = { version = "0.7", optional =
true }` with `[features] vfs = ["dep:forensic-vfs"]` (`core/Cargo.toml`). With
the feature off, `apfs-core` is a plain `Read + Seek` reader with no
`forensic-vfs` dependency; with it on, an APFS volume — and a mounted APFS
snapshot (`open_snapshot`/`snapshots`) — composes into the fleet's read-only VFS
stack. The dependency tracks published `forensic-vfs` registry versions
(migrated across 0.1 → 0.2 → 0.3 → 0.4 → 0.5 → 0.7 as the contract evolved; see
commits `e9000cc`, `888340d`, `b8d09db`, `5f72869`, `1b2cda5`).

## Consequences

Bare readers stay lean; fleet orchestration gets a uniform, immutable,
shareable filesystem handle for APFS containers and point-in-time snapshot
views. The cost is tracking `forensic-vfs`'s evolving trait surface (the git log
shows several catch-up bumps), and consumers must opt in with
`features = ["vfs"]` to get the adapter.
