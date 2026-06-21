//! Volume superblock (`apfs_superblock_t`, magic `APFS_MAGIC = 'BSPA'` →
//! "APSB" → LE `0x42535041`) and per-volume navigation roots.
//!
//! Each volume's APSB (Apple *APFS Reference*, `apfs_superblock_t`) carries the
//! volume's own object map (`apfs_omap_oid`), the file-system tree root
//! (`apfs_root_tree_oid`, a virtual oid resolved through the volume omap), the
//! extent-reference tree (`apfs_extentref_tree_oid`), the snapshot-metadata tree
//! (`apfs_snap_meta_tree_oid`), the volume role/flags, `apfs_volname`, and
//! **`apfs_modified_by[APFS_MAX_HIST]`** — the history of which OS versions
//! mounted/modified the volume (forensically valuable provenance). The
//! `apfs_meta_crypto` field is a `wrapped_meta_crypto_state_t`.

/// Volume superblock magic `APFS_MAGIC` ('BSPA', "APSB" in a hex dump).
pub const APFS_MAGIC: u32 = 0x4253_5041;

/// One `apfs_modified_by_t` provenance entry (which OS version touched the volume).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ModifiedBy {
    pub id: String,
    pub timestamp: i64,
    pub last_xid: u64,
}

/// A parsed volume, the entry point for path navigation.
pub struct ApfsVolume {
    // volume omap, root-tree oid, extentref/snap-meta tree oids, role, name,
    // apfs_modified_by[] … (stub)
}

impl ApfsVolume {
    /// Parse and validate an APSB (magic + checksum).
    pub fn parse(_block: &[u8]) -> crate::Result<Self> {
        todo!("P3: validate magic+cksum, decode tree oids, role, volname, modified_by")
    }

    /// The volume name (`apfs_volname`).
    #[must_use]
    pub fn name(&self) -> &str {
        todo!("P3")
    }

    /// OS-version provenance history (`apfs_modified_by`).
    #[must_use]
    pub fn modified_by(&self) -> &[ModifiedBy] {
        todo!("P3")
    }

    /// Resolve a path (`/a/b/c`) to an inode via DIR_REC navigation.
    ///
    /// # Errors
    /// Returns an error if any path component is not found.
    pub fn open_path(&self, _path: &str) -> crate::Result<crate::inode::Inode> {
        todo!("P3: name->DIR_REC->inode descent from root")
    }

    /// Load an inode by its file-system object id.
    pub fn inode(&self, _oid: u64) -> crate::Result<crate::inode::Inode> {
        todo!("P3: fs-tree lookup of INODE record")
    }
}
