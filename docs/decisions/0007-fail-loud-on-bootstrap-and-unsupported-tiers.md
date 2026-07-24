# 7. Fail loud on bootstrap and unsupported tiers, never degrade to wrong output

Date: 2026-07-24
Status: Accepted

## Context

The fleet Robustness discipline separates a *bootstrap/resolution* failure — a
prerequisite every downstream step depends on — from a per-item miss. A
bootstrap failure MUST surface as a loud, named diagnostic carrying the
offending value, never be absorbed into an empty or "none found" result, because
an `Ok(empty)` on a failed bootstrap is indistinguishable from genuinely clean
input and hides the defect. APFS bootstrap steps are: finding a checksum-valid
container superblock in the checkpoint ring, and resolving virtual oids through
the object map. Additionally, two APFS device/layout tiers are not yet
implemented — Fusion (tier-2) address translation, and the space-manager
chunk-info **address**-block (CAB) indirection tier — and mis-reading either
would silently produce wrong physical addresses.

## Decision

Model every bootstrap and unsupported-tier failure as a distinct, named
`ApfsError` variant that carries the offending value and location
(`core/src/lib.rs`): `NoValidSuperblock { checked, last_magic }`,
`ChecksumMismatch { block, stored, computed }`, `OmapUnresolved { oid, xid }`,
`UnexpectedObjectType { structure, expected, found }`, `UnsupportedFusion`,
`UnsupportedSpacemanCab { count }`, `FieldOutOfRange { structure, field, value,
cap }`, and `CycleGuard { cap }`. A Fusion container is detected at `open()` and
rejected loudly rather than mis-addressed (commit `290105c`, "detect Fusion at
open() and fail loud"; `66a71ca`, "translate_address fails loud instead of
panicking"). The analyzer's `audit_*` entry points surface `apfs-core`
read/parse errors rather than swallow them into an empty finding set
(`forensic/src/lib.rs` `Result` doc).

## Consequences

An examiner never receives a plausible-but-wrong empty result from a failed
bootstrap: a missing superblock, an unresolved oid, or an unsupported Fusion/CAB
tier stops with a named error and the raw value needed to diagnose it. The cost
is that the reader refuses input it cannot correctly handle (Fusion, CAB) rather
than best-efforting it — deliberate, since a forensic tool that emits wrong
addresses is worse than one that declines. These refusals convert to
implemented paths once a validating fixture exists.
