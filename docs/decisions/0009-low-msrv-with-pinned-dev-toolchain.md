# 9. Low CI-verified MSRV (1.85), pinned dev toolchain (1.96.0)

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy separates the *dev toolchain* (what you build/fmt/clippy
with) from the *declared MSRV* (`rust-version`, a downstream-facing promise).
Published libraries keep a low, CI-verified MSRV as a deliberate compatibility
feature — raising it narrows the crates.io audience and is treated as a
near-breaking change. `apfs-core` and `apfs-forensic` are both published
libraries (ADR 0002), not an examiner-run binary, so the library MSRV rule
applies.

## Decision

Declare `rust-version = "1.85"` once in `[workspace.package]` (`Cargo.toml`),
inherited by both members, as the low CI-verified floor. Pin the dev toolchain
separately to the current fleet stable in `rust-toolchain.toml`
(`channel = "1.96.0"`, `components = ["clippy", "rustfmt"]`) so all contributors
and CI build, format, and lint on one version. Develop on 1.96.0; promise only
1.85 to consumers.

## Consequences

Downstream tools on older toolchains can depend on the reader and auditor, while
contributors get a single, current, drift-free build/lint toolchain. The floor
is 1.85, higher than the fleet's usual 1.75/1.80 library floor; it is set to
match hfsplus-forensic, the sibling filesystem reader, which pins `1.85`. The
design plan records this reason directly ("hfsplus-forensic pins `1.85`; match it
(`rust-version = \"1.85\"`)"), so the floor is a deliberate fleet-consistency
choice with the neighbouring filesystem crate. Raising 1.85 later must be a
deliberate, CI-verified decision, not an accident of using a newer-Rust feature.
