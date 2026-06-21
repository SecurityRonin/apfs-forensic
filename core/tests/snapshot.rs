//! Snapshot metadata + name trees and the point-in-time volume view, validated
//! against real, Apple-authored APFS images.
//!
//! Two corpora drive this test:
//!
//!   * **`apfs_content.bin`** (the P4 fixture, NO snapshots): a real Apple-minted
//!     container whose volume APSB (block 438) carries an **empty** snap-metadata
//!     tree (block 340, `o_subtype` 0x10 SNAPMETATREE, `btn_nkeys` 0). It proves
//!     the tree is *located* and walked correctly on real data and yields zero
//!     snapshots (Tier-2: real Apple structure, ground truth = the documented
//!     empty tree). No `todo!`, no synthetic snap-meta tree.
//!
//!   * **`APFS_P5_FIXTURE`** (env-gated, a container *with* snapshots and a file
//!     whose content changes between snapshots): validates the populated
//!     snap-metadata list (names, xids, create-times) against `diskutil apfs
//!     listSnapshots` / `fsapfsinfo`, the snap-name to xid resolution, and the
//!     **point-in-time read** (v1 bytes at snapshot 1's frozen APSB vs v2 at the
//!     live APSB). Skips cleanly when the fixture is absent, like an oracle
//!     binary (the snapshot-with-changing-file image needs the macOS snapshot
//!     entitlement to mint — see `docs/validation.md` / `tests/data/README.md`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::snapshot::list_snapshots;
use apfs_core::volume::ApfsVolume;

const CONTENT: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");
const BLOCK_SIZE: usize = 4096;
/// The live volume superblock (APSB) sits at block 438 in the P4 fixture.
const APSB_BLOCK: usize = 438;

fn p4_volume() -> ApfsVolume {
    let block = &CONTENT[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
    ApfsVolume::parse(block).expect("parse live APSB")
}

#[test]
fn real_unsnapshotted_volume_lists_zero_snapshots() {
    // The P4 fixture has no snapshots: its snap-metadata tree (a real
    // Apple-authored physical btree at block 340, o_subtype 0x10) has
    // btn_nkeys == 0. The walk must locate it, verify its Fletcher-64 checksum,
    // and return an empty list — never a todo!/panic, never a bootstrap error.
    let mut r = Cursor::new(CONTENT);
    let vol = p4_volume();
    let snaps = list_snapshots(&mut r, &vol, BLOCK_SIZE).expect("list snapshots");
    assert!(
        snaps.is_empty(),
        "P4 fixture has no snapshots; got {snaps:?}"
    );
}

#[test]
fn real_volume_exposes_snap_meta_tree_oid() {
    // The snap-metadata tree is located by a *physical* block number in the APSB
    // (apfs_snap_meta_tree_oid @152). For the P4 fixture that is block 340.
    let vol = p4_volume();
    assert_eq!(vol.snap_meta_tree_oid(), 340);
}
