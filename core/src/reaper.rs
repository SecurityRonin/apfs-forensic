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

/// Read the reaper's pending objects (the in-progress object plus every queued
/// reap-list entry).
///
/// `reaper_paddr` is the live reaper's physical block (resolve it from the
/// container's checkpoint map). The reap lists are ephemeral objects chained by
/// `nrl_next`, so their oids are resolved to physical blocks through `mappings`
/// (the same checkpoint-map mappings used to locate the reaper).
pub fn pending_objects<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _reaper_paddr: u64,
    _mappings: &[crate::checkpoint::CheckpointMapping],
    _block_size: usize,
) -> crate::Result<Vec<ReapPending>> {
    todo!("P6: walk nx_reaper_phys_t -> nx_reap_list_phys_t entries")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::CheckpointMapping;
    use std::io::Cursor;

    const BS: usize = 4096;

    /// Stamp a valid Fletcher-64 over block `b` so `read_obj_block` trusts it.
    fn stamp(img: &mut [u8], b: usize) {
        let blk = &img[b * BS..(b + 1) * BS];
        let cks = crate::object::fletcher64_checksum(blk).to_le_bytes();
        img[b * BS..b * BS + 8].copy_from_slice(&cks);
    }

    fn put_u64(img: &mut [u8], b: usize, off: usize, v: u64) {
        img[b * BS + off..b * BS + off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(img: &mut [u8], b: usize, off: usize, v: u32) {
        img[b * BS + off..b * BS + off + 4].copy_from_slice(&v.to_le_bytes());
    }

    // Synthetic reaper → one reap list of two queued objects, chained by an
    // ephemeral oid resolved through the checkpoint mappings. Validates the walk
    // (header → reap-list → entries) that no committed fixture exercises.
    #[test]
    fn walks_reap_list_entries_via_mappings() {
        let mut img = vec![0u8; BS * 4];
        let reaper_b = 1usize;
        let list_b = 2usize;
        let list_oid = 0x4001u64;

        // Reaper header: nr_head/nr_tail point at the reap-list's ephemeral oid;
        // nr_oid == 0 (no in-progress object).
        put_u64(&mut img, reaper_b, 48, list_oid); // nr_head
        put_u64(&mut img, reaper_b, 56, list_oid); // nr_tail
        stamp(&mut img, reaper_b);

        // Reap list: nrl_next == 0 (end), nrl_count == 2, two entries at @64.
        put_u64(&mut img, list_b, 32, 0); // nrl_next
        put_u32(&mut img, list_b, 48, 2); // nrl_count
                                          // entry 0 @64: nrle_type@8, nrle_oid@24
        put_u32(&mut img, list_b, 64 + 8, 0x4000_000d); // FS object
        put_u64(&mut img, list_b, 64 + 24, 500);
        // entry 1 @104
        put_u32(&mut img, list_b, 104 + 8, 0x4000_0002); // BTREE object
        put_u64(&mut img, list_b, 104 + 24, 600);
        stamp(&mut img, list_b);

        let mappings = [CheckpointMapping {
            oid: list_oid,
            paddr: list_b as u64,
            obj_type: 0x8000_0012,
            subtype: 0,
        }];

        let mut r = Cursor::new(img);
        let pending = pending_objects(&mut r, reaper_b as u64, &mappings, BS).expect("walk");
        let got: Vec<(u64, u32)> = pending.iter().map(|p| (p.oid, p.obj_type)).collect();
        assert_eq!(got, vec![(500, 0x4000_000d), (600, 0x4000_0002)]);
    }

    // An in-progress object (nr_oid != 0) is reported even with no reap lists.
    #[test]
    fn reports_in_progress_object() {
        let mut img = vec![0u8; BS * 2];
        let reaper_b = 1usize;
        put_u64(&mut img, reaper_b, 48, 0); // nr_head == 0 (no lists)
        put_u32(&mut img, reaper_b, 72, 0x4000_000d); // nr_type
        put_u64(&mut img, reaper_b, 88, 777); // nr_oid
        stamp(&mut img, reaper_b);

        let mut r = Cursor::new(img);
        let pending = pending_objects(&mut r, reaper_b as u64, &[], BS).expect("read");
        assert_eq!(pending.len(), 1);
        assert_eq!((pending[0].oid, pending[0].obj_type), (777, 0x4000_000d));
    }
}
