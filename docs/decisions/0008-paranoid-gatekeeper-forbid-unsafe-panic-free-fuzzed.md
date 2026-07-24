# 8. Paranoid Gatekeeper: `forbid(unsafe)`, panic-free by lint, fuzzed

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse untrusted, attacker-controllable disk images. The fleet's
Paranoid Gatekeeper standard requires such crates to never panic, never read out
of bounds, and never trust a length field, enforced by a static lint posture
plus fuzzing. Unlike the mmap readers (ewf, memory-forensic) that downgrade to
`unsafe_code = "deny"` for one bounded mmap site, `apfs-core` reads over a plain
`Read + Seek` source and uses only pure-Rust codecs (ADR 0004), so it has no
justified `unsafe` site at all.

## Decision

Set `unsafe_code = "forbid"` at the workspace root (`Cargo.toml`
`[workspace.lints.rust]`), reasserted per crate (`#![forbid(unsafe_code)]` in
both `lib.rs`), giving a provable zero-memory-corruption surface (the
`unsafe forbidden` README badge). Add the panic-free lint pair
`unwrap_used = "deny"` and `expect_used = "deny"` (`[workspace.lints.clippy]`),
with `allow-unwrap-in-tests`/`allow-expect-in-tests` in `clippy.toml` so tests
may still unwrap to fail loudly. Back the static posture with fuzzing: one
`cargo-fuzz` target per parsed structure (`fuzz/fuzz_targets/`:
`nx_superblock`, `btree_node`, `object`, `fsrecord`) plus a full-pipeline
`fuzz_forensic` target. Robustness comes from bounds-checked reads
(`core/src/bytes.rs`), range-checked length/offset/count fields (the
`FieldOutOfRange` cap, ADR 0007), capped allocations, and cycle-guarded tree
walks (the `CycleGuard` cap).

## Consequences

The reader carries a compiler-proved memory-safety guarantee and a
lint-enforced no-panic posture, and the fuzz targets empirically exercise it
against malformed input. Per fleet evidence rules the headline claim is
"fuzzed" (measured) with "panic-free by lint" as the qualified static half —
never a bare unprovable "panic-free" absolute. The cost is that production code
may not use `unwrap`/`expect`; every fallible read must thread a `Result` or a
bounds-checked default, and defensive arms that are provably unreachable under a
dominating invariant are annotated `// cov:unreachable` rather than deleted to
satisfy the coverage gate (commits `a5a5c24`, `6fe8cef`).
