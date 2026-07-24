# 1. Build an APFS reader and auditor from scratch

Date: 2026-07-24
Status: Accepted

## Context

The fleet needs a forensic-grade Apple File System reader in the FILESYSTEM
layer: consume a CONTAINER sector stream (`Read + Seek`) and navigate by path
(name → inode → file-extents → bytes), the APFS analogue of NTFS's
`name → inode → data-runs`. The fleet's build-vs-reuse rule (research prior art
across crates.io first; reuse a maintained, better-scoped library rather than
reinvent) requires establishing that no such crate exists before writing one.

The design research (`docs/plans/2026-06-21-apfs-forensic-design.md` §1.1)
surveyed the ecosystem: the only crates that parse APFS are `apfs` 0.2.4
(read-only, ~771 downloads, embedded in an unrelated DMG-extraction tool) and
`exhume_apfs` 0.1.6 (~292 downloads, early-stage, no public repo). Neither is
forensic-grade, maintained as a library, nor exposes the raw structural detail
(slack, superseded checkpoints, deleted records) a forensic auditor needs.
Authoritative references, by contrast, are excellent: Apple's *Apple File System
Reference* (2020-06-22) is the primary on-disk spec, cross-checked against
libfsapfs's reverse-engineered format spec.

## Decision

Build `apfs-core` (reader) and `apfs-forensic` (auditor) from scratch, authored
against the Apple reference and cross-checked against libfsapfs. Treat the
existing crates plus `fsapfsinfo` (libfsapfs), The Sleuth Kit
`fsstat`/`fls`/`istat`, `apfsck` (apfsprogs), apfs-fuse, and macOS's own
read-only mount as independent validation **oracles** (Doer-Checker), never as
dependencies. The one piece reused rather than rebuilt is the transparent-
compression codec stack the fleet already owns (see ADR 0004).

## Consequences

The fleet gains a maintained, forensic-grade, pure-Rust APFS reader it controls
end to end, with the structural visibility an auditor requires. The cost is the
multi-week from-scratch build the design document scopes into phases P1–P9, and
the ongoing burden of tracking the spec ourselves. The prior-art crates and the
external tools remain valuable as cross-check oracles, which the validation
strategy (ADR 0007, `docs/validation.md`) depends on.
