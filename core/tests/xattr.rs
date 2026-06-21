//! Extended-attribute listing and symlink-target resolution, validated against
//! the REAL `apfs_content.bin` fixture and the macOS `xattr -l` / `readlink`
//! oracles.
//!
//! Ground truth (macOS `xattr -l` / `readlink` before detach — see
//! `tests/data/README.md`):
//!   /plain.txt        inode 18  xattrs: com.example.tag="forensic-marker-P4",
//!                                       user.note="second custom attr"
//!   /compressed.txt   inode 23  xattrs: com.apple.decmpfs (embedded header,
//!                                       type 8), com.apple.ResourceFork (stream)
//!   /symlink_to_beth  inode 29  com.apple.fs.symlink -> "Dir1/Beth.txt"
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::dir::open_path;
use apfs_core::volume::ApfsVolume;
use apfs_core::xattr::{
    get_xattr, list_xattrs, symlink_target, XattrValue, XATTR_NAME_DECMPFS,
    XATTR_NAME_RESOURCE_FORK,
};

const CONTENT: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");
const BLOCK_SIZE: usize = 4096;
const APSB_BLOCK: usize = 438;

fn volume() -> ApfsVolume {
    let block = &CONTENT[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
    ApfsVolume::parse(block).expect("parse live APSB")
}

fn inode_oid(path: &str) -> u64 {
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    open_path(&mut r, &vol, path, BLOCK_SIZE)
        .unwrap_or_else(|_| panic!("open {path}"))
        .oid
}

#[test]
fn lists_custom_xattrs_matching_xattr_l() {
    let oid = inode_oid("/plain.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let xattrs = list_xattrs(&mut r, &vol, oid, BLOCK_SIZE).expect("list xattrs");
    let named: Vec<(&str, &[u8])> = xattrs
        .iter()
        .map(|x| {
            let bytes: &[u8] = match &x.value {
                XattrValue::Embedded(b) => b,
                _ => &[],
            };
            (x.name.as_str(), bytes)
        })
        .collect();
    assert!(
        named.contains(&("com.example.tag", b"forensic-marker-P4".as_slice())),
        "got {named:?}"
    );
    assert!(
        named.contains(&("user.note", b"second custom attr".as_slice())),
        "got {named:?}"
    );
}

#[test]
fn get_xattr_returns_embedded_value() {
    let oid = inode_oid("/plain.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let v = get_xattr(&mut r, &vol, oid, "com.example.tag", BLOCK_SIZE)
        .expect("get_xattr")
        .expect("present");
    match v {
        XattrValue::Embedded(b) => assert_eq!(b, b"forensic-marker-P4"),
        other => panic!("expected embedded, got {other:?}"),
    }
}

#[test]
fn get_xattr_absent_is_none() {
    let oid = inode_oid("/plain.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    assert!(get_xattr(&mut r, &vol, oid, "no.such.attr", BLOCK_SIZE)
        .expect("get_xattr")
        .is_none());
}

#[test]
fn compressed_file_carries_decmpfs_and_resource_fork() {
    let oid = inode_oid("/compressed.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    // decmpfs is an embedded 16-byte header: magic 'cmpf', type 8, usize 180000.
    let decmpfs = get_xattr(&mut r, &vol, oid, XATTR_NAME_DECMPFS, BLOCK_SIZE)
        .expect("get decmpfs")
        .expect("decmpfs present");
    match decmpfs {
        XattrValue::Embedded(b) => {
            assert_eq!(&b[0..4], &0x636d_7066u32.to_le_bytes(), "magic 'cmpf'");
            assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 8, "type 8");
            assert_eq!(
                u64::from_le_bytes(b[8..16].try_into().unwrap()),
                180000,
                "uncompressed_size"
            );
        }
        other => panic!("decmpfs should be embedded, got {other:?}"),
    }
    // ResourceFork is a STREAM xattr (the bulk compressed payload).
    let fork = get_xattr(&mut r, &vol, oid, XATTR_NAME_RESOURCE_FORK, BLOCK_SIZE)
        .expect("get fork")
        .expect("fork present");
    match fork {
        XattrValue::Stream { dstream_oid, size } => {
            assert_eq!(dstream_oid, 24, "resource-fork dstream id");
            assert_eq!(size, 1526, "resource-fork compressed size");
        }
        other => panic!("ResourceFork should be a stream, got {other:?}"),
    }
}

#[test]
fn resource_fork_reads_back_the_stream_bytes() {
    let oid = inode_oid("/compressed.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let fork = apfs_core::xattr::resource_fork(&mut r, &vol, oid, BLOCK_SIZE)
        .expect("read fork")
        .expect("fork present");
    assert_eq!(fork.len(), 1526, "resource-fork size from the dstream");
    // The chunked LZVN fork header: little-endian headerSize 16, then end-offsets.
    assert_eq!(u32::from_le_bytes(fork[0..4].try_into().unwrap()), 16);
}

#[test]
fn resolves_symlink_target_matching_readlink() {
    let oid = inode_oid("/symlink_to_beth");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let target = symlink_target(&mut r, &vol, oid, BLOCK_SIZE)
        .expect("symlink_target")
        .expect("is a symlink");
    assert_eq!(target, "Dir1/Beth.txt", "must match readlink");
}

#[test]
fn non_symlink_has_no_symlink_target() {
    let oid = inode_oid("/plain.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    assert!(symlink_target(&mut r, &vol, oid, BLOCK_SIZE)
        .expect("symlink_target")
        .is_none());
}
