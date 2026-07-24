# 10. Publish via release-plz with `<crate>-vX.Y.Z` tags

Date: 2026-07-24
Status: Accepted

## Context

The fleet release law is that library crates publish through a reviewed,
conventional-commit-driven PR-bump-and-publish (release-plz), never a hand-cut
version bump — the release PR is the one reviewable checkpoint before an
irreversible crates.io publish, and it produces the changelog for free. A known
tag-collision trap exists: the app/CLI binary pipeline triggers on `v[0-9]*`
tags, so if release-plz cut a bare `vX.Y.Z` tag it would fire a binary build for
a library-only repo. This repo ships no end-user binary — only the two library
crates.

## Decision

Adopt release-plz (`release-plz.toml`, `.github/workflows/release-plz.yml`;
commit `7fa12c1`). On pushes to `main`, `release-pr` opens a human-reviewed
version-bump PR from conventional commits and `release` publishes any crate
whose `Cargo.toml` version is ahead of crates.io, in dependency order. Two
controls prevent the tag collision: `release_commits =
"^(feat|fix|perf|refactor|doc|revert)"` (so chore/ci/test/style/build, including
release-plz's own release commits, never prepare a release — killing the
changelog-churn loop), and `git_tag_name = "{{ package }}-v{{ version }}"`
(commit `4583bf8`), so tags read `apfs-core-v0.2.6` / `apfs-forensic-v0.2.2` —
a `<name>-v…` tag has a letter after the first `v`, never matching a `v[0-9]*`
binary trigger. `apfs-core` and `apfs-forensic` version independently
(`dependencies_update = false`); library crates get a tag + CHANGELOG, not a
GitHub Release (`git_release_enable = false`). The `apfs-forensic-fuzz` member
carries its own `[workspace]` so release-plz never sees it.

## Consequences

Each publish is a reviewed, one-click PR merge with an auto-generated changelog,
and the two crates release on their own cadence. The `<crate>-v` tag prefix
keeps a library publish from ever masquerading as a binary release. The trade-off
is the discipline release-plz assumes: conventional-commit types drive the bump,
the release PR must be merged with a merge commit (not squash), and an
API-changing `feat` must regenerate any public-API baseline in the same release.
