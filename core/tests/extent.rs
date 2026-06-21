//! File-extent assembly + sparse-hole handling, validated against the REAL
//! `apfs_content.bin` fixture and the macOS `cp`/`cat` SHA-256 oracle.
//!
//! Ground truth (macOS `shasum -a 256` of each file before detach — see
//! `docs/validation.md` / `tests/data/README.md`):
//!   /plain.txt        inode 18  35 B    sha256 289af0a0…  (single extent, phys 347)
//!   /sparse.bin       inode 22  69632 B sha256 fe0fc4fa…  (HOLE phys 0 + tail phys 371)
//!   /Dir1/Beth.txt    inode 28  33 B    sha256 ee7c2682…  (single extent, phys 400)
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::dir::open_path;
use apfs_core::extent::read_data;
use apfs_core::volume::ApfsVolume;
use sha2::{Digest, Sha256};

const CONTENT: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");
const BLOCK_SIZE: usize = 4096;
/// The live volume superblock (APSB, xid 14) sits at block 438 in the fixture.
const APSB_BLOCK: usize = 438;

fn volume() -> ApfsVolume {
    let block = &CONTENT[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
    ApfsVolume::parse(block).expect("parse live APSB")
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn reads_plain_file_byte_identical() {
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/plain.txt", BLOCK_SIZE).expect("open plain.txt");
    let bytes = read_data(&mut r, &vol, &inode, BLOCK_SIZE).expect("read plain.txt");
    assert_eq!(bytes.len(), 35);
    assert_eq!(
        &bytes, b"APFS P4 plain file. Hello extents.\n",
        "plain content must match"
    );
    assert_eq!(
        sha256_hex(&bytes),
        "289af0a0b21ede77675f1173c65cc2388d3b26570dbaaa7f2506444e05abf86b",
        "plain.txt SHA-256 must match macOS cp"
    );
}

#[test]
fn reads_sparse_file_with_hole_byte_identical() {
    // sparse.bin is 69632 logical bytes: a 64 KiB hole (phys 0) then a 4 KiB
    // tail extent at logical offset 65536. The hole must read back as zeroes and
    // the tail truncated to the DSTREAM size.
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/sparse.bin", BLOCK_SIZE).expect("open sparse.bin");
    let bytes = read_data(&mut r, &vol, &inode, BLOCK_SIZE).expect("read sparse.bin");
    assert_eq!(bytes.len(), 69632, "logical size honoured");
    // The hole region [0, 65536) is all zero.
    assert!(
        bytes[..65536].iter().all(|&b| b == 0),
        "sparse hole must be zero-filled"
    );
    // The tail [65536, 69632) is real data (non-zero somewhere).
    assert!(
        bytes[65536..].iter().any(|&b| b != 0),
        "sparse tail carries data"
    );
    assert_eq!(
        sha256_hex(&bytes),
        "fe0fc4fa9e8465dd74086a9e37d21d1a69c0f4d08cf6b9abbb288886d4cc822a",
        "sparse.bin SHA-256 must match macOS cp"
    );
}

#[test]
fn reads_nested_file_byte_identical() {
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/Dir1/Beth.txt", BLOCK_SIZE).expect("open Beth.txt");
    let bytes = read_data(&mut r, &vol, &inode, BLOCK_SIZE).expect("read Beth.txt");
    assert_eq!(bytes.len(), 33);
    assert_eq!(
        sha256_hex(&bytes),
        "ee7c26829909d9c7ea1bcb444908fff35c1254f3c51894bd49b8b175becfeb96",
        "Beth.txt SHA-256 must match macOS cp"
    );
}

#[test]
fn list_extents_reports_hole_and_tail() {
    // The lower-level extent list surfaces the raw records, including the
    // sparse hole (phys_block_num 0).
    use apfs_core::extent::list_extents;
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/sparse.bin", BLOCK_SIZE).expect("open sparse.bin");
    let extents = list_extents(&mut r, &vol, inode.private_id, BLOCK_SIZE).expect("list extents");
    // Two extents: a 64 KiB hole at offset 0, a 4 KiB tail at 65536.
    assert_eq!(extents.len(), 2, "got {extents:?}");
    let hole = extents.iter().find(|e| e.logical_offset == 0).unwrap();
    assert_eq!(hole.phys_block_num, 0, "first extent is a hole");
    assert_eq!(hole.len, 65536);
    let tail = extents.iter().find(|e| e.logical_offset == 65536).unwrap();
    assert_ne!(tail.phys_block_num, 0, "tail is backed by a physical block");
    assert_eq!(tail.len, 4096);
}
