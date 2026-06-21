//! Extended attributes (`APFS_TYPE_XATTR 4`, value `j_xattr_val_t`).
//!
//! `j_xattr_val_t { u16 flags; u16 xdata_len; u8 xdata[] }` (Apple *APFS
//! Reference*). Either `XATTR_DATA_EMBEDDED` (data inline in `xdata`) or
//! `XATTR_DATA_STREAM` (`xdata` holds a `j_dstream_t` referencing a data stream)
//! must be set. Forensically important named xattrs:
//! - `com.apple.decmpfs` — transparent compression header ([`crate::compression`]).
//! - `com.apple.ResourceFork` — resource fork / non-embedded compressed payload.
//! - `com.apple.fs.symlink` / symlink target (a symlink's target is its data
//!   stream, but related metadata appears in xattrs).
//! - quarantine, `FinderInfo`, security.* (provenance leads).

/// `XATTR_DATA_EMBEDDED` flag (data inline in the record).
pub const XATTR_DATA_EMBEDDED: u16 = 0x0002;
/// `XATTR_DATA_STREAM` flag (data in a referenced stream).
pub const XATTR_DATA_STREAM: u16 = 0x0001;

/// A parsed extended attribute.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Xattr {
    pub name: String,
    pub flags: u16,
    /// Embedded bytes, or a marker that the payload is in a stream.
    pub embedded: Option<Vec<u8>>,
}

/// List the xattrs of an inode.
pub fn list_xattrs<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _volume: &crate::volume::ApfsVolume,
    _inode_oid: u64,
) -> crate::Result<Vec<Xattr>> {
    todo!("P4: fs-tree scan for XATTR records under inode_oid")
}
