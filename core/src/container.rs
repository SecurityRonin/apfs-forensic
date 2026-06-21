//! Container superblock (`nx_superblock_t`, magic `NX_MAGIC = 'BSXN'` →
//! "NXSB" → LE `0x4253584E`) and container geometry.
//!
//! The NXSB (Apple *APFS Reference*, `nx_superblock_t`) names the block size
//! (`nx_block_size`, default 4096, max 65536), block count, feature/incompatible
//! flags, container UUID, the spaceman/omap/reaper oids, the checkpoint
//! descriptor + data areas (`nx_xp_desc_base/len`, `nx_xp_data_base/len`), and
//! the volume oids (`nx_fs_oid[]`). Block 0 holds *a* copy, but the **live**
//! superblock is found via the checkpoint ring ([`crate::checkpoint`]).
//!
//! The EFI jumpstart (`nx_efi_jumpstart`, magic `NX_EFI_JUMPSTART_MAGIC =
//! 'RDSJ'` → "JSDR") locates the bootable EFI driver, parsed here for
//! completeness.

/// Container superblock magic `NX_MAGIC` ('BSXN', "NXSB" in a hex dump).
pub const NX_MAGIC: u32 = 0x4253_584E;

/// Smallest / default / largest block size and minimum container size (Apple).
pub const NX_MINIMUM_BLOCK_SIZE: u32 = 4096;
pub const NX_DEFAULT_BLOCK_SIZE: u32 = 4096;
pub const NX_MAXIMUM_BLOCK_SIZE: u32 = 65536;
pub const NX_MINIMUM_CONTAINER_SIZE: u64 = 1_048_576;

/// A parsed container superblock (subset; `#[non_exhaustive]` for additive growth).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NxSuperblock {
    /// `nx_block_size` — the authoritative block size (never assumed).
    pub block_size: u32,
    /// `nx_block_count`.
    pub block_count: u64,
    /// Container object-map oid (`nx_omap_oid`).
    pub omap_oid: u64,
    /// Volume oids (`nx_fs_oid[]`), one per APSB volume.
    pub fs_oids: Vec<u64>,
    // checkpoint areas, spaceman/reaper oids, feature flags, uuid … (stub)
}

impl NxSuperblock {
    /// Parse and validate an NXSB from a block (checks magic + checksum).
    ///
    /// # Errors
    /// [`crate::ApfsError::NoValidSuperblock`] on bad magic;
    /// [`crate::ApfsError::ChecksumMismatch`] on a Fletcher-64 failure.
    pub fn parse(_block: &[u8]) -> crate::Result<Self> {
        todo!("P1: validate magic + cksum, decode geometry, checkpoint areas, fs_oids")
    }
}
