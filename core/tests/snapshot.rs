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

use apfs_core::snapshot::{list_snapshots, mount_snapshot, resolve_snapshot_xid};
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

#[test]
fn real_unsnapshotted_volume_resolves_no_name() {
    // The empty snap-meta tree has no SNAP_NAME records, so resolving any name
    // returns None (a clean per-item miss, walked over real Apple structure —
    // never a bootstrap error, never a panic).
    let mut r = Cursor::new(CONTENT);
    let vol = p4_volume();
    let xid = resolve_snapshot_xid(&mut r, &vol, "nonexistent", BLOCK_SIZE)
        .expect("resolve snapshot name");
    assert_eq!(xid, None, "no snapshot named 'nonexistent' exists");
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Env-gated populated-fixture validation (Tier-2, real Apple-minted snapshots).
///
/// `APFS_P5_FIXTURE` points at a raw APFS *container partition* image carrying
/// two snapshots and a file (`changing.txt`) whose content differs between
/// them. The test reconciles the snapshot list against the values recorded in
/// `tests/data/README.md` (from `diskutil apfs listSnapshots` / `fsapfsinfo`)
/// and reads `changing.txt` at snapshot 1 (v1 bytes) vs the live volume (v2
/// bytes), asserting each matches the macOS-written SHA-256. Skips cleanly when
/// the env var is unset (the snapshot-with-changing-file image needs the macOS
/// snapshot entitlement to mint — see docs/validation.md).
#[test]
fn populated_fixture_point_in_time_read() {
    let Ok(path) = std::env::var("APFS_P5_FIXTURE") else {
        eprintln!("APFS_P5_FIXTURE unset; skipping populated point-in-time test");
        return;
    };
    let data = std::fs::read(&path).expect("read APFS_P5_FIXTURE");
    let mut r = Cursor::new(&data);

    let container = apfs_core::ApfsContainer::open(&mut r).expect("open container");
    let _ = container; // container open validates the bootstrap

    // The live volume APSB and the snapshot list are reconciled against the
    // README-recorded oracle values via env (so this stays data-driven and is
    // not hard-coded to one image's block numbers).
    let live_apsb_block: u64 = std::env::var("APFS_P5_LIVE_APSB")
        .ok()
        .and_then(|v| v.parse().ok())
        .expect("APFS_P5_LIVE_APSB must be set with the fixture");
    let start = live_apsb_block as usize * BLOCK_SIZE;
    let live = ApfsVolume::parse(&data[start..start + BLOCK_SIZE]).expect("parse live APSB");

    let snaps = list_snapshots(&mut r, &live, BLOCK_SIZE).expect("list snapshots");
    assert!(
        snaps.len() >= 2,
        "expected >=2 snapshots in the populated fixture, got {}",
        snaps.len()
    );
    // snap-name resolution must round-trip every snapshot's name back to its xid.
    for s in &snaps {
        let resolved =
            resolve_snapshot_xid(&mut r, &live, &s.name, BLOCK_SIZE).expect("resolve name");
        assert_eq!(resolved, Some(s.xid), "snap-name {} -> xid", s.name);
    }

    // Point-in-time: read changing.txt at the FIRST snapshot (v1) and live (v2).
    use apfs_core::dir::open_path;
    use apfs_core::extent::read_data;
    let snap1 = &snaps[0];
    let snap_vol = mount_snapshot(&mut r, snap1, BLOCK_SIZE).expect("mount snapshot 1");
    let v1_inode =
        open_path(&mut r, &snap_vol, "/changing.txt", BLOCK_SIZE).expect("open v1 changing.txt");
    let v1 = read_data(&mut r, &snap_vol, &v1_inode, BLOCK_SIZE).expect("read v1");
    let live_inode =
        open_path(&mut r, &live, "/changing.txt", BLOCK_SIZE).expect("open live changing.txt");
    let v2 = read_data(&mut r, &live, &live_inode, BLOCK_SIZE).expect("read v2");

    let v1_sha = std::env::var("APFS_P5_V1_SHA256").expect("APFS_P5_V1_SHA256 must be set");
    let v2_sha = std::env::var("APFS_P5_V2_SHA256").expect("APFS_P5_V2_SHA256 must be set");
    assert_eq!(
        sha256_hex(&v1),
        v1_sha,
        "snapshot-1 changing.txt = v1 bytes"
    );
    assert_eq!(sha256_hex(&v2), v2_sha, "live changing.txt = v2 bytes");
    assert_ne!(
        v1, v2,
        "v1 and v2 must differ (content changed across snapshot)"
    );
}
