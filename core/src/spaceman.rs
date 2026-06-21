//! Space manager (`spaceman_phys_t`, type `OBJECT_TYPE_SPACEMAN 0x5`) and
//! allocation bitmaps.
//!
//! The space manager tracks which container blocks are allocated. It references
//! chunk-info blocks (`chunk_info_block_t`, type `SPACEMAN_CIB 0x7`) and
//! chunk-info-address blocks (`cib_addr_block_t`, type `SPACEMAN_CAB 0x6`) that
//! point at allocation bitmaps (`SPACEMAN_BITMAP 0x8`), plus free queues
//! (`SPACEMAN_FREE_QUEUE 0x9`) of blocks pending release. The forensic value is
//! the "is this physical block currently free?" predicate — input to
//! deleted-extent carve-candidate reasoning (a free bitmap is necessary but
//! **not** sufficient for recoverability; see the analyzer).

/// Query whether a physical block is marked free in the allocation bitmaps.
pub fn is_block_free<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _spaceman_paddr: u64,
    _block: u64,
) -> crate::Result<bool> {
    todo!("P6: resolve CAB/CIB chain, read allocation bitmap bit for `block`")
}
