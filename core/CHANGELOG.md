# Changelog

All notable changes to `apfs-core` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.7](https://github.com/SecurityRonin/apfs-forensic/compare/apfs-core-v0.2.6...apfs-core-v0.2.7) - 2026-09-07

### Added

- *(filevault)* GREEN - files on an encrypted volume read as plaintext
- *(filevault)* GREEN - the encrypted fs-tree decrypts under the VEK
- *(filevault)* read-only unlock_check that works on a 2 TB image
- *(filevault)* GREEN - the unlock chain runs from ranged reads
- *(filevault)* GREEN - volume unlock works end to end
- *(filevault)* GREEN - locate a volume's wrapped VEK and keybag extent
- *(filevault)* GREEN - decrypt the container keybag
- *(filevault)* GREEN - AES-KW unwrap and PBKDF2-SHA256 key derivation
- *(filevault)* GREEN - parse the wrapped-KEK object from a volume keybag

## [0.2.6](https://github.com/SecurityRonin/apfs-forensic/compare/apfs-core-v0.2.5...apfs-core-v0.2.6) - 2026-07-22

### Added

- *(apfs)* GREEN — real unallocated-extent enumeration via spaceman

## [0.2.4](https://github.com/SecurityRonin/apfs-forensic/compare/apfs-core-v0.2.3...apfs-core-v0.2.4) - 2026-07-19

### Fixed

- *(deps)* bump forensic-vfs 0.4 -> 0.5

## [0.2.2]

### Changed

- Migrate to forensic-vfs 0.3 (FsKind newtype). The `vfs` adapter's `kind()` now
  returns the string-backed `FsKind::APFS` const (re-exported from
  `forensicnomicon-core`) instead of the removed `enum FsKind::Apfs` variant.
