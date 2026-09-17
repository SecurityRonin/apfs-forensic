//! Extended attributes must be reachable through the `forensic-vfs` interface.
//!
//! `apfs-core` reads them (`xattr::list_xattrs`/`get_xattr`, Tier-1 validated in
//! `dfvfs_tier1.rs` against dfVFS's own expectations), but the VFS adapter never
//! surfaced them: `FileSystem::data_streams` has a DEFAULT returning an empty
//! list, and this adapter did not override it.
//!
//! The consequence reached all the way to the end user. Every consumer built on
//! forensic-vfs — including `4n6mount` — was told that no file anywhere has an
//! extended attribute, so an examiner running `xattr -l` on a mounted evidence
//! file saw "none" regardless of what the image contained. On macOS that hides
//! the quarantine flag, Finder metadata and decmpfs.
//!
//! A default that silently means "nothing here" is the dangerous kind: it makes
//! an unimplemented method indistinguishable from an empty result.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Read as _};

use forensic_vfs::{FileSystem, StreamId, StreamKind};

/// dfVFS's APFS image, whose `a_directory/a_file` carries `myxattr`
/// = `My extended attribute` — their generator writes it and their own suite
/// asserts it, so the expectation is not ours.
fn image() -> Vec<u8> {
    let gz = include_bytes!("../../tests/data/dfvfs/apfs.raw.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .expect("fixture decompresses");
    out
}

fn open() -> impl FileSystem {
    apfs_core::vfs::ApfsFs::open(Cursor::new(image())).expect("apfs opens")
}

/// Resolve a path to its `FileId`.
fn find(fs: &impl FileSystem, path: &str) -> forensic_vfs::FileId {
    let mut id = fs.root();
    for part in path.split('/') {
        id = fs
            .lookup(id, part.as_bytes())
            .expect("lookup")
            .unwrap_or_else(|| panic!("{part} not found"));
    }
    id
}

/// RED: `data_streams` must report the file's extended attributes.
#[test]
fn data_streams_reports_extended_attributes() {
    let fs = open();
    let id = find(&fs, "a_directory/a_file");

    let streams = fs.data_streams(id).expect("data_streams");
    let xattrs: Vec<_> = streams
        .iter()
        .filter(|s| s.kind == StreamKind::Xattr)
        .collect();

    assert!(
        !xattrs.is_empty(),
        "dfVFS writes `myxattr` on this file; data_streams reported {} stream(s), \
         none of them an extended attribute",
        streams.len()
    );
    assert!(
        xattrs
            .iter()
            .any(|s| s.name.as_deref() == Some(b"myxattr".as_slice())),
        "the attribute must be reported under its own NAME, not an index: {:?}",
        xattrs.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
}

/// RED: and `read_at` must return the attribute's VALUE.
///
/// Listing a name while failing to read it would be worse than not listing it —
/// an examiner would see the attribute exists and be unable to say what it says.
#[test]
fn read_at_returns_the_attribute_value() {
    let fs = open();
    let id = find(&fs, "a_directory/a_file");

    let s = fs
        .data_streams(id)
        .expect("data_streams")
        .into_iter()
        .find(|s| s.name.as_deref() == Some(b"myxattr".as_slice()))
        .expect("myxattr must be listed");

    assert!(matches!(s.id, StreamId::Xattr(_)), "addressed as an xattr stream");

    let mut buf = vec![0u8; usize::try_from(s.size).unwrap_or(0).max(64)];
    let n = fs.read_at(id, s.id, 0, &mut buf).expect("read the attribute");
    buf.truncate(n);
    assert_eq!(
        buf.as_slice(),
        b"My extended attribute",
        "the value dfVFS asserts, byte for byte"
    );
}

/// RED: the default data stream must still be readable and must NOT be
/// reclassified as an attribute.
#[test]
fn the_default_stream_is_untouched() {
    let fs = open();
    let id = find(&fs, "a_directory/another_file");
    let mut buf = vec![0u8; 64];
    let n = fs
        .read_at(id, StreamId::Default, 0, &mut buf)
        .expect("default stream still reads");
    buf.truncate(n);
    assert_eq!(buf.as_slice(), b"This is another file.\n");
}
