//! Generic B-tree node walker (`btree_node_phys_t`, types `OBJECT_TYPE_BTREE
//! 0x2` / `OBJECT_TYPE_BTREE_NODE 0x3`).
//!
//! Every APFS index (omap, fs-tree, snapshot-metadata tree, extent-reference
//! tree, fext-tree) is a B-tree built from `btree_node_phys_t` blocks. The node
//! header (Apple *APFS Reference*, 24 bytes after the object header):
//! `btn_flags u16`, `btn_level u16` (0 = leaf), `btn_nkeys u32`, then four
//! `nloc_t` regions (`btn_table_space`, `btn_free_space`, `btn_key_free_list`,
//! `btn_val_free_list`), then `btn_data[]`.
//!
//! Entries (libfsapfs) are either **fixed-size** (4 bytes: `key_offs u16`,
//! `value_offs u16`) or **variable-size** (adds key/value lengths). A root node
//! carries a `btree_info_t` footer at the end of the block. Walks are
//! cycle-guarded and allocation-capped (`btn_nkeys` is range-checked before use).

/// A B-tree node header.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct BTreeNodeHeader {
    pub flags: u16,
    /// 0 = leaf node.
    pub level: u16,
    pub nkeys: u32,
}

/// A key/value pair yielded by a leaf walk (borrowed from the node buffer).
pub struct Entry<'a> {
    pub key: &'a [u8],
    pub value: &'a [u8],
}

/// Parse a node header (bounds-checked).
#[must_use]
pub fn parse_node_header(_block: &[u8]) -> Option<BTreeNodeHeader> {
    todo!("P2: decode btn_flags/level/nkeys + nloc_t regions")
}

/// Iterate the entries of a single node (fixed or variable layout), without
/// descending. Returns an empty iterator on a malformed node (never panics).
#[must_use]
pub fn node_entries(_block: &[u8]) -> Vec<Entry<'_>> {
    todo!("P2: split entries by fixed/variable layout, bounds-checked offsets")
}
