# 4. Reuse the fleet decmpfs codec stack; prefer our own `lzvn-core`

Date: 2026-07-24
Status: Accepted

## Context

APFS files can be transparently compressed with decmpfs, reusing the same
DEFLATE/LZVN/LZFSE codecs as HFS+. The fleet already owns and validated this
stack in `hfsplus-forensic` against real macOS data. Two fleet rules apply: the
"prefer our own crates" rule (reach for a SecurityRonin crate over a third
party where one exists) and the `unsafe`-avoidance posture (ADR 0008) — any
codec pulled in must be pure-Rust so it does not introduce C-FFI or force a
downgrade of `unsafe_code = "forbid"`. A naming trap exists: the bare `lzvn`
crate on crates.io is an unrelated third party (Reverier-Xu) with a `decode_raw`
API and no tolerance for decmpfs trailing bytes, whereas the fleet's own
length-tolerant decoder is `lzvn-core`.

## Decision

Reuse the existing pure-Rust codec stack rather than reimplement any codec:
`flate2` (zlib/DEFLATE, decmpfs types 3/4), `lzfse_rust` (LZFSE, types 11/12),
and the fleet's own `lzvn` — declared as
`lzvn = { version = "0.1", package = "lzvn-core" }` (`Cargo.toml` lines 33–39) —
for length-tolerant LZVN (types 7/8). Type codes and the decmpfs map itself live
in the KNOWLEDGE leaf `forensicnomicon` (ADR 0005). This keeps
`apfs-core::compression` a thin dispatcher over vetted decoders.

## Consequences

decmpfs decode is a solved, already-validated problem the crate inherits, and
all three decoders are pure-Rust, so `unsafe_code = "forbid"` stays intact.
Choosing `lzvn-core` over the third-party `lzvn` is deliberate: only the fleet
decoder handles decmpfs trailing-byte tolerance (the property `hfsplus-forensic`
validated 25/25 on real macOS Tahoe data), so pulling the bare `lzvn` would have
mis-decoded real compressed files. The trade-off is a dependency on fleet crate
release cadence, which the fleet manages through its shared Renovate/release-plz
pipeline.
