//! Checkpoint descriptor + data ring, and resolution of the **live** container
//! superblock.
//!
//! APFS writes superblocks transactionally into a ring of checkpoint blocks. To
//! find the current container state (Apple *APFS Reference*, "Mounting an APFS
//! container"): scan the checkpoint **descriptor area** for the
//! `nx_superblock_t` with the **highest `xid` that also has a valid Fletcher-64
//! checksum**, then read the checkpoint **map** (`checkpoint_map_phys_t`, type
//! `OBJECT_TYPE_CHECKPOINT_MAP 0xc`) to resolve the ephemeral oids it references
//! (spaceman, reaper) to physical addresses.
//!
//! Non-latest checkpoints reference superseded objects — this is normal
//! copy-on-write history, and is a **recovery opportunity** (the analyzer reads
//! it as residue, never as an anomaly).

/// One `checkpoint_mapping_t` entry (ephemeral oid → paddr at a type/subtype).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct CheckpointMapping {
    pub oid: u64,
    pub paddr: u64,
    pub obj_type: u32,
    pub subtype: u32,
}

/// Resolution of the live superblock from the checkpoint ring.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LiveCheckpoint {
    /// Block address of the chosen (highest-valid-xid) NXSB.
    pub superblock_paddr: u64,
    /// Its transaction id.
    pub xid: u64,
    /// Ephemeral oid → paddr mappings from the checkpoint map.
    pub mappings: Vec<CheckpointMapping>,
}

/// Scan the descriptor area and return the live checkpoint.
///
/// # Errors
/// [`crate::ApfsError::NoValidSuperblock`] if no cksum-valid NXSB exists in the
/// ring — a loud bootstrap failure, never an empty `Ok`.
pub fn resolve_live_checkpoint<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _bootstrap: &crate::container::NxSuperblock,
) -> crate::Result<LiveCheckpoint> {
    todo!("P1: scan descriptor area for highest-valid-xid NXSB, read checkpoint map")
}
