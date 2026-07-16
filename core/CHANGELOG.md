# Changelog

All notable changes to `apfs-core` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2]

### Changed

- Migrate to forensic-vfs 0.3 (FsKind newtype). The `vfs` adapter's `kind()` now
  returns the string-backed `FsKind::APFS` const (re-exported from
  `forensicnomicon-core`) instead of the removed `enum FsKind::Apfs` variant.
