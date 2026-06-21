//! Directory records (`APFS_TYPE_DIR_REC 9`) and name→inode navigation.
//!
//! A directory entry's key is `j_drec_key_t` (parent oid + name) or, on
//! case-insensitive/normalization-aware volumes, `j_drec_hashed_key_t` (parent
//! oid + a 32-bit name hash + name). The value `j_drec_val_t { u64 file_id;
//! u64 date_added; u16 flags; u8 xfields[] }` (Apple *APFS Reference*) gives the
//! target inode (`file_id`) and the time the entry was added (`date_added`,
//! distinct from the inode's own timestamps — not updated on rename-in-place).
//!
//! Navigation walks the fs-tree for `DIR_REC` keys under a parent oid, matching
//! the requested name (honoring the volume's `apfs_incompatible_features`
//! case/normalization flags).

/// A directory entry.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DirEntry {
    pub name: String,
    pub file_id: u64,
    pub date_added: u64,
    pub flags: u16,
}

/// List the entries of a directory (parent oid).
pub fn list_dir<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _volume: &crate::volume::ApfsVolume,
    _parent_oid: u64,
) -> crate::Result<Vec<DirEntry>> {
    todo!("P3: fs-tree scan for DIR_REC under parent_oid")
}
