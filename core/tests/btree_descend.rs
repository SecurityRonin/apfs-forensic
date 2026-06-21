//! B-tree root→leaf descent (`for_each_leaf_entry`): visits every leaf entry,
//! verifying each node's Fletcher-64 checksum and guarding against cyclic node
//! links. Validated against the REAL self-minted omap B-tree (block 344, a
//! single root+leaf node) and synthetic multi-level / cyclic nodes for the
//! defensive paths. See `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::btree::{self, BTreeSubtype};
use apfs_core::object::fletcher64_checksum;
use apfs_core::ApfsError;

const CHAIN: &[u8] = include_bytes!("../../tests/data/apfs_container_chain.bin");
const BLOCK_SIZE: usize = 4096;

#[test]
fn descend_real_omap_tree_visits_single_leaf_entry() {
    // The container omap B-tree root is at block (paddr) 344. Walking it visits
    // exactly one leaf entry: omap_key(oid=1026, xid=2) -> omap_val(paddr=342).
    let mut reader = Cursor::new(CHAIN);
    let mut seen: Vec<(u64, u64, u64)> = Vec::new();
    btree::for_each_leaf_entry(
        &mut reader,
        344,
        BLOCK_SIZE,
        BTreeSubtype::Omap,
        &mut |k, v| {
            let oid = u64::from_le_bytes(k[0..8].try_into().unwrap());
            let xid = u64::from_le_bytes(k[8..16].try_into().unwrap());
            let paddr = u64::from_le_bytes(v[8..16].try_into().unwrap());
            seen.push((oid, xid, paddr));
        },
    )
    .expect("walk omap tree");
    assert_eq!(seen, vec![(1026, 2, 342)]);
}

#[test]
fn descend_rejects_checksum_mismatch_node() {
    // Corrupt the omap root node's body so Fletcher-64 fails: the walk must
    // error (checksum-before-trust), never read the corrupted TOC.
    let mut img = CHAIN.to_vec();
    img[344 * BLOCK_SIZE + 100] ^= 0xff;
    let mut reader = Cursor::new(img);
    match btree::for_each_leaf_entry(
        &mut reader,
        344,
        BLOCK_SIZE,
        BTreeSubtype::Omap,
        &mut |_, _| {},
    ) {
        Err(ApfsError::ChecksumMismatch { .. }) => {}
        other => panic!("expected ChecksumMismatch, got {other:?}"),
    }
}

#[test]
fn descend_guards_against_self_cycle() {
    // A two-block image where an INDEX node at block 0 points its only child
    // back at itself: the cycle guard must fire (CycleGuard), never loop forever.
    let mut img = vec![0u8; BLOCK_SIZE * 2];
    // Build a non-leaf (index) node at block 0, fixed-KV, 1 entry whose value is
    // the 8-byte child block number 0 (itself).
    let node = &mut img[0..BLOCK_SIZE];
    // btn_flags @32 = ROOT | FIXED (no LEAF); btn_level @34 = 1; btn_nkeys @36 = 1
    node[32..34].copy_from_slice(&(0x1u16 | 0x4u16).to_le_bytes());
    node[34..36].copy_from_slice(&1u16.to_le_bytes());
    node[36..40].copy_from_slice(&1u32.to_le_bytes());
    // btn_table_space @40 (nloc off=0, len=4)
    node[40..42].copy_from_slice(&0u16.to_le_bytes());
    node[42..44].copy_from_slice(&4u16.to_le_bytes());
    // TOC entry @ btn_data(56): key_offs=0, value_offs=8 (8-byte child value).
    node[56..58].copy_from_slice(&0u16.to_le_bytes());
    node[58..60].copy_from_slice(&8u16.to_le_bytes());
    // key area starts at 56+0+4 = 60; omap_key (16 B) — content irrelevant.
    // value: val_base = block.len() - btree_info(40); value at val_base-8 = child#.
    let val_base = BLOCK_SIZE - 40;
    node[val_base - 8..val_base].copy_from_slice(&0u64.to_le_bytes()); // child = block 0
                                                                       // recompute the node checksum so it passes the cksum gate
    let cks = fletcher64_checksum(node);
    node[0..8].copy_from_slice(&cks.to_le_bytes());

    let mut reader = Cursor::new(img);
    match btree::for_each_leaf_entry(
        &mut reader,
        0,
        BLOCK_SIZE,
        BTreeSubtype::Omap,
        &mut |_, _| {},
    ) {
        Err(ApfsError::CycleGuard { .. }) => {}
        other => panic!("expected CycleGuard, got {other:?}"),
    }
}
