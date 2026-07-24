# 3. Publish `apfs-core` but import as `apfs_core` (name collision)

Date: 2026-07-24
Status: Accepted

## Context

The fleet naming grammar (`ronin-issen/CLAUDE.md`) says a reader is
`<x>-core`, imported bare as `<x>` via `[lib] name = "<x>"` when the short name
is free, but when the bare `<x>` crate is taken on crates.io by an unrelated
third party the import path stays `<x>_core` (the `ntfs-core` precedent, which
keeps `ntfs_core` rather than hijack Colin Finck's popular `ntfs`). The bare
`apfs` crate name is already claimed on crates.io by Dil4rd's unrelated
read-only parser (design plan §1.1).

## Decision

Publish the reader as the crate `apfs-core` with `[lib] name = "apfs_core"`
(`core/Cargo.toml` lines 19–21), so consumers write `use apfs_core::…` and never
collide with, or appear to hijack, the third-party `apfs` crate. The analyzer
stays `apfs-forensic`. The inter-crate dependency is declared once in
`[workspace.dependencies]` as
`apfs-core = { path = "core", version = "0.2.6", package = "apfs-core" }`.

## Consequences

The import path is stable and unambiguous (`apfs_core`), and there is no risk of
a consumer confusing our reader with the pre-existing `apfs` crate — which
instead serves as a cross-check oracle (ADR 0001). The minor cost is the
slightly longer import token versus a bare `apfs`, accepted per the fleet
precedent. Consumers are insulated from the package/lib-name distinction because
the workspace declares the `package = "apfs-core"` mapping in one place.
