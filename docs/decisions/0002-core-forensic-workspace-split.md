# 2. Two-crate `core/` + `forensic/` workspace split

Date: 2026-07-24
Status: Accepted

## Context

The fleet's Crate-structure standard (`ronin-issen/CLAUDE.md` — "reader/analyzer
split") mandates that every single-format repo be one workspace named
`<x>-forensic` with two members: `core/` → crate `<x>-core` (the raw
reader/parser, no findings) and `forensic/` → crate `<x>-forensic` (the anomaly
auditor emitting `forensicnomicon::report::Finding`). The reference
implementation is `ntfs-forensic`. The rationale is that a `-core` reader is
built to read *valid* data robustly, so it normalizes away exactly the detail an
auditor must see; separating the two lets each be consumed and versioned
independently, and lets the auditor drop below the reader's happy-path API when
an audit needs raw structure.

## Decision

Ship one workspace (`Cargo.toml` `members = ["core", "forensic"]`) with
`apfs-core` (the reader: NXSB container + checkpoint ring, object map, B-trees,
APSB volumes, `j_key` records, extents, xattrs, snapshots, space manager,
encryption state, decmpfs) and `apfs-forensic` (the auditor: a typed
`AnomalyKind` enum plus `audit_container`/`audit_volume` entry points that
convert anomalies into graded findings). `apfs-forensic` depends on `apfs-core`
(`forensic/Cargo.toml` → `apfs-core = { workspace = true }`) — the default
direction — and the two crates version independently (`apfs-core` 0.2.6,
`apfs-forensic` 0.2.2; `workspace.package` deliberately does not hoist
`version`).

## Consequences

A downstream Rust tool that only wants the reader depends on `apfs-core` alone
and never compiles the auditor. Anomaly findings aggregate uniformly with the
partition and container layers through the shared report model (ADR 0005). The
split obliges the reader to expose enough structural detail that the auditor
does not have to re-parse the image itself; where a future audit needs
lower-level access (e.g. sealed-volume hash recomputation over raw file-info),
the standard permits `apfs-forensic` to read raw bytes directly rather than
contort through a normalizing reader API.
