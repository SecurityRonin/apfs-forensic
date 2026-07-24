# 5. Depend on `forensicnomicon` for format constants and the report model

Date: 2026-07-24
Status: Accepted

## Context

Two cross-cutting fleet concerns must not be re-invented per repo: (1) the
KNOWLEDGE leaf `forensicnomicon` owns format constants — magics, object-type
codes, the decmpfs type map — so the parsing *algorithms* live in the reader but
the constant *tables* live once in the leaf; and (2) `forensicnomicon::report`
is the single normalized reporting vocabulary (`Severity`, `Category`,
`Observation`, `Finding`, `Source`) that every fleet analyzer emits, so
ORCHESTRATION (Issen) and a future GUI render all analyzers uniformly instead of
N bespoke `XxxAnalysis` types.

## Decision

Both crates depend on `forensicnomicon` (`= "1"`, `workspace.dependencies`).
`apfs-core` uses it for magics/type codes/decmpfs map (`core/lib.rs` states the
constant tables live in the leaf, the algorithms here). `apfs-forensic` keeps a
typed `AnomalyKind` domain enum (its APFS knowledge) and implements
`forensicnomicon::report::Observation` to convert each variant into a graded
`Finding` (`forensic/lib.rs`). Every anomaly maps to a published,
scheme-prefixed SCREAMING-KEBAB `code` (e.g. `APFS-SEALED-VOLUME-BROKEN`,
`APFS-XID-REUSE`) that is never changed once shipped. Findings are framed as
observations ("consistent with …"), never verdicts.

## Consequences

APFS anomalies aggregate into one `forensicnomicon::report::Report` alongside
partition- and container-layer findings with no adapter glue. The `code`
strings become a published contract the fleet depends on, which constrains
future renaming (new variants get new codes). `#[non_exhaustive]` on
`AnomalyKind` and on the shared report enums keeps the model additively
evolvable. The reader carries no duplicate constant tables, at the cost of a
hard dependency on the leaf's release cadence.
