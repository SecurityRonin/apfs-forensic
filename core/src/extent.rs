//! File extents (`APFS_TYPE_FILE_EXTENT 8`, value `j_file_extent_val_t`) and
//! file byte assembly.
//!
//! A file's content is described by a data stream (`APFS_TYPE_DSTREAM_ID 6` /
//! the inode's `INO_EXT_TYPE_DSTREAM` xfield giving `j_dstream_t { size,
//! alloced_size, … }`) plus a series of `FILE_EXTENT` records keyed by logical
//! offset. Each `j_file_extent_val_t { u64 len_and_flags; u64 phys_block_num;
//! u64 crypto_id }` (Apple *APFS Reference*) carries the extent length
//! (`len_and_flags & J_FILE_EXTENT_LEN_MASK 0x00ffffffffffffff`, a multiple of
//! the block size) and the starting physical block. A `phys_block_num` of 0 is a
//! sparse hole.
//!
//! `read_data` assembles extents in logical order into plaintext bytes; if the
//! inode carries a `com.apple.decmpfs` xattr, [`crate::compression`] is applied
//! transparently instead (the `FILE_EXTENT` path holds the resource-fork payload
//! for non-embedded compression).

/// Mask for the extent length within `len_and_flags`.
pub const J_FILE_EXTENT_LEN_MASK: u64 = 0x00ff_ffff_ffff_ffff;

/// One file extent.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct FileExtent {
    /// Logical offset within the file (from the record key).
    pub logical_offset: u64,
    /// Length in bytes (`len_and_flags & J_FILE_EXTENT_LEN_MASK`).
    pub len: u64,
    /// Starting physical block (0 = sparse hole).
    pub phys_block_num: u64,
}

/// Assemble a file's full byte content (applying decmpfs if present).
pub fn read_data<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _volume: &crate::volume::ApfsVolume,
    _inode: &crate::inode::Inode,
) -> crate::Result<Vec<u8>> {
    todo!("P4: gather DSTREAM + FILE_EXTENT, read blocks, apply decmpfs if xattr present")
}
