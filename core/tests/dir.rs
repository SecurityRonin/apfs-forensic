//! Directory record (`DIR_REC`) listing and **name→inode path navigation**,
//! validated against the REAL fs-tree fixture and the independent TSK `fls`/
//! `istat` oracle.
//!
//! Ground truth (TSK `fls -r` / `istat` + macOS `stat` on the same image — see
//! `docs/validation.md`): the known tree is
//!   /                inode 2  (root)
//!   /top.txt         inode 22  size 15
//!   /Dir1            inode 18
//!   /Dir1/Beth.txt   inode 20  size 38
//!   /Dir1/Sub        inode 19
//!   /Dir1/Sub/secret.bin  inode 21  size 26
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::dir::{list_dir, lookup_child, open_path};
use apfs_core::volume::ApfsVolume;

const FSTREE: &[u8] = include_bytes!("../../tests/data/apfs_fstree.bin");
const BLOCK_SIZE: usize = 4096;
/// The APSB (volume superblock) sits at block 371 in the fixture.
const APSB_BLOCK: usize = 371;

/// `ROOT_DIR_INO_NUM` (Apple) — the inode number of a volume's root directory.
const ROOT_DIR_INO_NUM: u64 = 2;

fn volume() -> ApfsVolume {
    let block = &FSTREE[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
    ApfsVolume::parse(block).expect("parse APSB")
}

#[test]
fn list_root_directory() {
    // Root (inode 2) contains top.txt(22), Dir1(18), and the system .fseventsd
    // (16). fls -r shows exactly these at the root.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let mut entries = list_dir(&mut r, &vol, ROOT_DIR_INO_NUM, BLOCK_SIZE).expect("list root");
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let named: Vec<(&str, u64)> = entries
        .iter()
        .map(|e| (e.name.as_str(), e.file_id))
        .collect();
    assert!(named.contains(&("top.txt", 22)), "got {named:?}");
    assert!(named.contains(&("Dir1", 18)), "got {named:?}");
    assert!(named.contains(&(".fseventsd", 16)), "got {named:?}");
}

#[test]
fn list_dir1_children() {
    // Dir1 (inode 18) contains Beth.txt(20) and Sub(19).
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let entries = list_dir(&mut r, &vol, 18, BLOCK_SIZE).expect("list Dir1");
    let named: Vec<(&str, u64)> = entries
        .iter()
        .map(|e| (e.name.as_str(), e.file_id))
        .collect();
    assert!(named.contains(&("Beth.txt", 20)), "got {named:?}");
    assert!(named.contains(&("Sub", 19)), "got {named:?}");
    assert_eq!(entries.len(), 2);
}

#[test]
fn lookup_child_resolves_single_component() {
    // (parent=2, "Dir1") -> 18; (parent=18, "Beth.txt") -> 20.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    assert_eq!(
        lookup_child(&mut r, &vol, ROOT_DIR_INO_NUM, "Dir1", BLOCK_SIZE).unwrap(),
        Some(18)
    );
    assert_eq!(
        lookup_child(&mut r, &vol, 18, "Beth.txt", BLOCK_SIZE).unwrap(),
        Some(20)
    );
}

#[test]
fn lookup_child_missing_is_none() {
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    assert_eq!(
        lookup_child(&mut r, &vol, ROOT_DIR_INO_NUM, "nope", BLOCK_SIZE).unwrap(),
        None
    );
}

#[test]
fn open_path_resolves_top_level_file() {
    // /top.txt -> inode 22, size 15.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/top.txt", BLOCK_SIZE).expect("open /top.txt");
    assert_eq!(inode.oid, 22);
    assert_eq!(inode.size, Some(15));
    assert_eq!(inode.name.as_deref(), Some("top.txt"));
    assert_eq!(inode.parent_id, ROOT_DIR_INO_NUM);
}

#[test]
fn open_path_resolves_nested_file() {
    // /Dir1/Beth.txt -> inode 20, size 38, parent 18.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/Dir1/Beth.txt", BLOCK_SIZE).expect("open Beth");
    assert_eq!(inode.oid, 20);
    assert_eq!(inode.size, Some(38));
    assert_eq!(inode.parent_id, 18);
}

#[test]
fn open_path_resolves_deeply_nested_file() {
    // /Dir1/Sub/secret.bin -> inode 21, size 26, parent 19.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/Dir1/Sub/secret.bin", BLOCK_SIZE).expect("open secret");
    assert_eq!(inode.oid, 21);
    assert_eq!(inode.size, Some(26));
    assert_eq!(inode.parent_id, 19);
}

#[test]
fn open_path_root_returns_root_inode() {
    // "/" resolves to the root directory inode (2).
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/", BLOCK_SIZE).expect("open root");
    assert_eq!(inode.oid, ROOT_DIR_INO_NUM);
}

#[test]
fn open_path_missing_component_errors() {
    // A non-existent path component is a loud per-item miss, not a panic.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    assert!(open_path(&mut r, &vol, "/Dir1/missing.txt", BLOCK_SIZE).is_err());
    assert!(open_path(&mut r, &vol, "/nope/Beth.txt", BLOCK_SIZE).is_err());
}

#[test]
fn open_path_handles_trailing_and_double_slashes() {
    // Empty path components (from "//" or a trailing "/") are skipped, so these
    // resolve identically to the canonical form.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let a = open_path(&mut r, &vol, "/Dir1/", BLOCK_SIZE).expect("trailing slash");
    assert_eq!(a.oid, 18);
    let b = open_path(&mut r, &vol, "/Dir1//Sub", BLOCK_SIZE).expect("double slash");
    assert_eq!(b.oid, 19);
}
