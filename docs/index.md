# apfs-forensic

A pure-Rust, from-scratch APFS (Apple File System) reader (`apfs-core`) and graded
anomaly auditor (`apfs-forensic`), following the SecurityRonin fleet
reader/analyzer split.

> **Status: design skeleton.** See the design document at
> `docs/plans/2026-06-21-apfs-forensic-design.md`. Parser bodies are stubs.

- **`apfs-core`** — container/checkpoint/omap/btree/volume/fs-records/extents/
  xattrs/snapshots/spaceman/encryption + transparent decmpfs, over `Read + Seek`.
- **`apfs-forensic`** — APFS anomaly codes (`APFS-SNAPSHOT-*`, `APFS-OMAP-*`,
  `APFS-CHECKPOINT-*`, `APFS-SEALED-VOLUME-*`, `APFS-DELETED-*`, `APFS-CLONE-*`,
  `APFS-ENCRYPTION-*`, `APFS-TIMESTAMP-*`) emitted as
  `forensicnomicon::report::Finding`s.

See [Validation](validation.md) for the oracle + corpus plan.
