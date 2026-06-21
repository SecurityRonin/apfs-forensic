//! Volume superblock (APSB, `apfs_superblock_t`) parsing, validated against the
//! REAL self-minted fs-tree fixture (`apfs_fstree.bin`). The APSB sits at block
//! 371; its fields are cross-checked against the independent TSK `pstat` oracle
//! (volume `APFSP3`, APSB block 371, oid 1026, xid 6) and libfsapfs's
//! `fsapfs_volume_superblock` struct. See `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apfs_core::volume::{ApfsVolume, APFS_MAGIC};

const FSTREE: &[u8] = include_bytes!("../../tests/data/apfs_fstree.bin");
const BLOCK_SIZE: usize = 4096;

fn block(idx: usize) -> &'static [u8] {
    &FSTREE[idx * BLOCK_SIZE..(idx + 1) * BLOCK_SIZE]
}

#[test]
fn parse_apsb_magic_and_tree_oids() {
    // Block 371 is the volume superblock. apfs_omap_oid -> block 366 (physical
    // volume omap), apfs_root_tree_oid -> 1028 (a virtual oid resolved through
    // the volume omap). Verified verbatim from the raw image + libfsapfs struct.
    let v = ApfsVolume::parse(block(371)).expect("parse APSB");
    assert_eq!(APFS_MAGIC, 0x4253_5041);
    assert_eq!(v.omap_oid(), 366);
    assert_eq!(v.root_tree_oid(), 1028);
}

#[test]
fn parse_apsb_name_and_role() {
    // Volume name "APFSP3" (apfs_volname, a NUL-terminated UTF-8 string at
    // offset 704). diskutil/pstat both report the volume name as APFSP3.
    let v = ApfsVolume::parse(block(371)).expect("parse APSB");
    assert_eq!(v.name(), "APFSP3");
}

#[test]
fn parse_apsb_fs_index() {
    // apfs_fs_index (offset 36) is 0 for the only volume in the container.
    let v = ApfsVolume::parse(block(371)).expect("parse APSB");
    assert_eq!(v.fs_index(), 0);
}

#[test]
fn parse_apsb_rejects_wrong_magic() {
    // A block whose signature is not "APSB" is not a volume superblock.
    let mut b = block(371).to_vec();
    b[32..36].copy_from_slice(b"XXXX");
    // Recompute checksum so we exercise the magic gate, not the cksum gate.
    let cks = apfs_core::object::fletcher64_checksum(&b);
    b[0..8].copy_from_slice(&cks.to_le_bytes());
    match ApfsVolume::parse(&b) {
        Err(apfs_core::ApfsError::UnexpectedObjectType { found, .. }) => {
            assert_eq!(found, u32::from_le_bytes(*b"XXXX"));
        }
        other => panic!("expected UnexpectedObjectType, got {other:?}"),
    }
}

#[test]
fn parse_apsb_rejects_checksum_mismatch() {
    // Flip a byte in the APSB body: the Fletcher-64 gate must reject it before
    // any field is trusted (checksum-before-trust).
    let mut b = block(371).to_vec();
    b[200] ^= 0xff;
    match ApfsVolume::parse(&b) {
        Err(apfs_core::ApfsError::ChecksumMismatch { .. }) => {}
        other => panic!("expected ChecksumMismatch, got {other:?}"),
    }
}

#[test]
fn parse_apsb_rejects_short_block() {
    // A truncated block (too short for the APSB header) yields a loud error,
    // never a panic.
    assert!(ApfsVolume::parse(&[0u8; 16]).is_err());
}
