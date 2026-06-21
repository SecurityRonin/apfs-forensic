//! End-to-end container open: read block 0, resolve the checkpoint ring to the
//! live superblock, expose its geometry. Validated against the REAL self-minted
//! container (Tier 2). See `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::ApfsContainer;

const HEAD: &[u8] = include_bytes!("../../tests/data/apfs_nxsb_head.bin");

#[test]
fn open_resolves_live_superblock_geometry() {
    let container = ApfsContainer::open(Cursor::new(HEAD)).expect("open container");
    let nx = container.superblock();
    // The live superblock (descriptor xid 2) — values cross-checked against
    // diskutil info (block size, UUID) and the raw bytes.
    assert_eq!(nx.block_size, 4096);
    assert_eq!(nx.block_count, 32758);
    assert_eq!(nx.xid, 2);
    assert_eq!(nx.omap_oid, 343);
    assert_eq!(nx.fs_oids, vec![1026]);
    assert_eq!(
        nx.uuid,
        [
            0x40, 0x11, 0x50, 0x33, 0x95, 0x23, 0x44, 0x96, 0x96, 0xa2, 0x0e, 0xda, 0xde, 0xec,
            0xa5, 0x65
        ]
    );
    // The checkpoint resolved the live superblock at descriptor block 4.
    assert_eq!(container.live_superblock_paddr(), 4);
}

#[test]
fn open_fails_loud_on_garbage_source() {
    // No NXSB magic anywhere -> loud bootstrap failure, never Ok.
    let garbage = vec![0u8; 4096 * 2];
    assert!(ApfsContainer::open(Cursor::new(garbage)).is_err());
}

#[test]
fn open_fails_loud_on_truncated_source() {
    // Source shorter than one block -> bootstrap failure, not a panic.
    let tiny = vec![0u8; 16];
    assert!(ApfsContainer::open(Cursor::new(tiny)).is_err());
}
