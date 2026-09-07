//! Tier-1 validation of the core reader against dfVFS's `apfs.raw`.
//!
//! Every other fixture in this repo is self-minted, which caps it at Tier 2 by
//! construction: an image we made, holding content we wrote, checked against
//! expectations we chose, confirms us and not the format. The decoder and the
//! answer key share an author, so they share his mistakes.
//!
//! This file removes our authorship from all three:
//!
//! | input | author |
//! |---|---|
//! | `apfs.raw` | dfVFS (log2timeline), Apache-2.0 |
//! | expected tree, inode numbers, sizes | dfVFS `tests/vfs/apfs_file_entry.py` |
//! | expected file bytes, xattr value | dfVFS `utils/generate_test_data_macos.sh` |
//!
//! Read the expectations from `APFSFileEntryTest` (the plain `apfs.raw` class).
//! That file declares `_IDENTIFIER_*` twice — again inside
//! `APFSFileEntryTestEncrypted` with different values — and taking the wrong
//! set produces a red that looks exactly like a decoder bug. It already did
//! once, in the encrypted suite, and the reader was right both times.

// An integration test is its own crate, so the workspace's panic-free lints
// apply here too and must be allowed explicitly, exactly as the sibling
// suites do. Production code keeps them denied.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Read as _};

use apfs_core::volume::ApfsVolume;

/// dfVFS `APFSFileEntryTest._IDENTIFIER_A_DIRECTORY`.
const IDENTIFIER_A_DIRECTORY: u64 = 16;
/// dfVFS `APFSFileEntryTest._IDENTIFIER_A_FILE`.
const IDENTIFIER_A_FILE: u64 = 17;
/// dfVFS `APFSFileEntryTest._IDENTIFIER_ANOTHER_FILE`.
const IDENTIFIER_ANOTHER_FILE: u64 = 19;
/// dfVFS `APFSFileEntryTest._IDENTIFIER_A_LINK`.
const IDENTIFIER_A_LINK: u64 = 20;

/// APFS root directory inode (`ROOT_DIR_INO_NUM`).
const ROOT_INO: u64 = 2;

/// dfVFS's unencrypted APFS container, decompressed.
///
/// Unlike `apfs_encrypted.dmg` this is a bare container, not a GPT disk, so it
/// needs no partition offset.
fn image() -> Vec<u8> {
    let gz = include_bytes!("../../tests/data/dfvfs/apfs.raw.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .expect("dfVFS apfs.raw must decompress");
    out
}

/// Resolve the single volume in the container, through the container omap.
fn volume(img: &[u8], cur: &mut Cursor<&[u8]>) -> (ApfsVolume, usize) {
    let nx = apfs_core::container::NxSuperblock::parse(&img[..4096]).expect("NXSB parses");
    let block_size = nx.block_size as usize;
    let read_block = |paddr: u64| -> Vec<u8> {
        let start = paddr as usize * block_size;
        img[start..start + block_size].to_vec()
    };
    let nx_omap = apfs_core::omap::ObjectMap::parse(&read_block(nx.omap_oid)).expect("omap parses");
    let fs_oid = *nx.fs_oids.first().expect("one volume");
    let entry = nx_omap
        .resolve(cur, fs_oid, u64::MAX, block_size)
        .expect("volume resolves");
    let vol = ApfsVolume::parse(&read_block(entry.paddr)).expect("APSB parses");
    (vol, block_size)
}

/// TIER 1: the root listing matches dfVFS's `expected_sub_file_entry_names`.
#[test]
fn root_listing_matches_dfvfs() {
    let img = image();
    let mut cur = Cursor::new(&img[..]);
    let (vol, block_size) = volume(&img, &mut cur);

    let mut names: Vec<String> = apfs_core::dir::list_dir(&mut cur, &vol, ROOT_INO, block_size)
        .expect("root lists")
        .into_iter()
        .map(|e| e.name)
        .collect();
    names.sort();

    assert_eq!(
        names,
        vec![".fseventsd", "a_directory", "a_link", "passwords.txt"],
        "dfVFS pins the root at exactly these four entries"
    );
}

/// TIER 1: `a_directory` holds the three files dfVFS's generator wrote.
///
/// dfVFS asserts `number_of_sub_file_entries == 3`; the generator names them.
#[test]
fn a_directory_holds_the_three_generated_files() {
    let img = image();
    let mut cur = Cursor::new(&img[..]);
    let (vol, block_size) = volume(&img, &mut cur);

    let mut names: Vec<String> =
        apfs_core::dir::list_dir(&mut cur, &vol, IDENTIFIER_A_DIRECTORY, block_size)
            .expect("a_directory lists")
            .into_iter()
            .map(|e| e.name)
            .collect();
    names.sort();

    assert_eq!(names.len(), 3, "dfVFS pins this at 3 sub-entries");
    assert_eq!(names, vec!["a_file", "a_resourcefork", "another_file"]);
}

/// TIER 1: inode numbers resolved through the tree match dfVFS's, and file
/// bytes match its generator's heredocs exactly.
///
/// Bytes, never sizes. A length assertion passes on wrong content of the right
/// length — a hole found the hard way in the encrypted suite, where a corrupted
/// extent tweak sailed through `len() == 22`.
#[test]
fn inode_numbers_and_file_bytes_match_dfvfs() {
    let img = image();
    let mut cur = Cursor::new(&img[..]);
    let (vol, block_size) = volume(&img, &mut cur);

    let another = apfs_core::dir::open_path(&mut cur, &vol, "a_directory/another_file", block_size)
        .expect("another_file resolves");
    assert_eq!(another.oid, IDENTIFIER_ANOTHER_FILE);
    let data = apfs_core::extent::read_data(&mut cur, &vol, &another, block_size).expect("reads");
    assert_eq!(
        data.as_slice(),
        b"This is another file.\n",
        "must equal the generator's heredoc"
    );

    let a_file = apfs_core::dir::open_path(&mut cur, &vol, "a_directory/a_file", block_size)
        .expect("a_file resolves");
    assert_eq!(a_file.oid, IDENTIFIER_A_FILE);
    let data = apfs_core::extent::read_data(&mut cur, &vol, &a_file, block_size).expect("reads");
    assert_eq!(
        data.as_slice(),
        b"This is a text file.\n\nWe should be able to parse it.\n",
        "must equal the generator's multi-line heredoc, blank line included"
    );
}

/// TIER 1: the extended attribute dfVFS writes and asserts.
///
/// `xattr -w myxattr "My extended attribute" .../a_file`, checked in dfVFS as
/// `test_attribute.name == "myxattr"` and value `b"My extended attribute"`.
#[test]
fn xattr_name_and_value_match_dfvfs() {
    let img = image();
    let mut cur = Cursor::new(&img[..]);
    let (vol, block_size) = volume(&img, &mut cur);

    let a_file = apfs_core::dir::open_path(&mut cur, &vol, "a_directory/a_file", block_size)
        .expect("a_file resolves");

    let names = apfs_core::xattr::list_xattrs(&mut cur, &vol, a_file.oid, block_size)
        .expect("xattrs list")
        .into_iter()
        .map(|x| x.name)
        .collect::<Vec<_>>();
    assert!(
        names.iter().any(|n| n == "myxattr"),
        "dfVFS writes myxattr on this file; got {names:?}"
    );

    let value = apfs_core::xattr::get_xattr(&mut cur, &vol, a_file.oid, "myxattr", block_size)
        .expect("myxattr reads")
        .expect("myxattr is present");

    // An xattr value is either inline or held in its own data stream. Resolve
    // both rather than assuming the small case: which one APFS chose is its
    // decision, not ours, and a test that only handles one would break on a
    // longer value for reasons unrelated to correctness.
    let bytes = match value {
        apfs_core::xattr::XattrValue::Embedded(b) => b,
        apfs_core::xattr::XattrValue::Stream { dstream_oid, size } => {
            apfs_core::extent::read_stream(&mut cur, &vol, dstream_oid, size, block_size)
                .expect("xattr stream reads")
        }
        // XattrValue is #[non_exhaustive]. A silent catch-all here would turn a
        // future storage form into a passing test that read nothing.
        other => panic!("unhandled xattr storage form: {other:?}"),
    };
    assert_eq!(
        bytes.as_slice(),
        b"My extended attribute",
        "the value dfVFS asserts, byte for byte"
    );
}

/// TIER 1: the symlink dfVFS creates resolves to the path its generator used.
///
/// `ln -s a_directory/another_file a_link`, and dfVFS asserts the linked entry
/// is named `another_file`.
#[test]
fn symlink_target_matches_dfvfs() {
    let img = image();
    let mut cur = Cursor::new(&img[..]);
    let (vol, block_size) = volume(&img, &mut cur);

    let link =
        apfs_core::dir::open_path(&mut cur, &vol, "a_link", block_size).expect("a_link resolves");
    assert_eq!(link.oid, IDENTIFIER_A_LINK);

    let target = apfs_core::xattr::symlink_target(&mut cur, &vol, link.oid, block_size)
        .expect("symlink target reads")
        .expect("a_link is a symlink and must have a target");
    assert_eq!(
        target, "a_directory/another_file",
        "the exact path passed to ln -s"
    );
}

/// TIER 1: the resource fork dfVFS's generator writes.
///
/// `echo "My resource fork" > .../a_resourcefork/..namedfork/rsrc`. Reading a
/// named fork is a distinct path from the data stream, and until now was
/// covered only by fixtures we minted.
#[test]
fn resource_fork_content_matches_dfvfs() {
    let img = image();
    let mut cur = Cursor::new(&img[..]);
    let (vol, block_size) = volume(&img, &mut cur);

    let rf = apfs_core::dir::open_path(&mut cur, &vol, "a_directory/a_resourcefork", block_size)
        .expect("a_resourcefork resolves");

    let fork = apfs_core::xattr::resource_fork(&mut cur, &vol, rf.oid, block_size)
        .expect("resource fork reads")
        .expect("this file has a resource fork");
    assert_eq!(
        fork.as_slice(),
        b"My resource fork\n",
        "echo appends a newline; the generator is the authority on both"
    );
}
