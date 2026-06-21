//! Object map (`omap_phys_t`, type `OBJECT_TYPE_OMAP 0xb`) and virtual-oid
//! resolution.
//!
//! A *virtual* object's oid is not its block address; it is resolved through an
//! object map at a given transaction id. The omap header (Apple *APFS
//! Reference*, `omap_phys_t`) points at a B-tree (`om_tree_oid`) whose keys are
//! `omap_key_t { oid, xid }` (16 bytes) and whose values are `omap_val_t
//! { flags, size, paddr }`. Looking up `(virtual_oid, xid)` yields the physical
//! block address of the object as of that transaction — the mechanism behind
//! both live access and point-in-time snapshot views.
//!
//! `om_flags` (e.g. `OMAP_MANUALLY_MANAGED 0x1`, `OMAP_ENCRYPTING 0x2`,
//! `OMAP_KEYROLLING 0x8`) describe snapshot/encryption state.

/// A resolved object-map entry.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct OmapEntry {
    pub oid: u64,
    pub xid: u64,
    pub paddr: u64,
    pub size: u32,
    pub flags: u32,
}

/// An object map and its backing B-tree.
pub struct ObjectMap {
    // tree root paddr, snapshot tree oid, flags … (stub)
}

impl ObjectMap {
    /// Parse the `omap_phys_t` header from a block.
    pub fn parse(_block: &[u8]) -> crate::Result<Self> {
        todo!("P2: decode omap_phys_t, capture tree oids + flags")
    }

    /// Resolve `(virtual_oid, xid)` to a physical block address by walking the
    /// omap B-tree (most-recent xid ≤ requested).
    ///
    /// # Errors
    /// [`crate::ApfsError::OmapUnresolved`] if no mapping exists.
    pub fn resolve<R: std::io::Read + std::io::Seek>(
        &self,
        _reader: &mut R,
        _oid: u64,
        _xid: u64,
    ) -> crate::Result<OmapEntry> {
        todo!("P2: btree lookup with xid<=requested, cycle/alloc guarded")
    }
}
