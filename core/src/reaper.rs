//! Reaper (`nx_reaper_phys_t`, type `OBJECT_TYPE_NX_REAPER 0x11`) — lazy object
//! deletion state.
//!
//! Large objects (e.g. a deleted volume or a dropped snapshot's extents) are not
//! freed atomically; the reaper records them on a `nx_reap_list_phys_t`
//! (`OBJECT_TYPE_NX_REAP_LIST 0x12`) and releases their space incrementally
//! across transactions. The forensic value: objects queued in the reaper are
//! **logically deleted but still physically present** — a residue lead the
//! analyzer surfaces (`APFS-REAPER-PENDING-OBJECT`, Info/Low).

/// An object pending reaping (logically deleted, physically present).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ReapPending {
    pub oid: u64,
    pub obj_type: u32,
}

/// Read the reaper's pending list.
pub fn pending_objects<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _reaper_paddr: u64,
) -> crate::Result<Vec<ReapPending>> {
    todo!("P6: walk nx_reaper_phys_t -> nx_reap_list_phys_t entries")
}
