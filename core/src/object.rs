//! Object header (`obj_phys_t`) parsing and Fletcher-64 checksum verification.
//!
//! Every APFS on-disk object begins with a 32-byte header
//! (Apple *APFS Reference*, `obj_phys_t`; `MAX_CKSUM_SIZE = 8`):
//!
//! | off | size | field        |
//! |-----|------|--------------|
//! | 0   | 8    | `o_cksum`    | Fletcher-64 checksum |
//! | 8   | 8    | `o_oid`      | object identifier    |
//! | 16  | 8    | `o_xid`      | transaction id       |
//! | 24  | 4    | `o_type`     | type + storage flags |
//! | 28  | 4    | `o_subtype`  | subtype              |
//!
//! `o_type & OBJECT_TYPE_MASK (0x0000ffff)` selects the object type;
//! `OBJ_STORAGETYPE_MASK (0xc0000000)` carries physical/ephemeral/virtual flags.
//!
//! Object-type constants (complete, from Apple): `INVALID 0x0`, `NX_SUPERBLOCK
//! 0x1`, `BTREE 0x2`, `BTREE_NODE 0x3`, `SPACEMAN 0x5`, …, `OMAP 0xb`,
//! `CHECKPOINT_MAP 0xc`, `FS 0xd`, `FSTREE 0xe`, …, `INTEGRITY_META 0x1e`,
//! `FEXT_TREE 0x1f`, plus the keybag 4CC object types. The authoritative table
//! lives in [`forensicnomicon`]; this module decodes against it.

/// Size in bytes of the `obj_phys_t` header.
pub const OBJ_PHYS_LEN: usize = 32;

/// A parsed object header.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ObjPhys {
    /// Stored Fletcher-64 checksum (`o_cksum`).
    pub cksum: u64,
    /// Object identifier (`o_oid`) — for a physical object, its block address.
    pub oid: u64,
    /// Transaction identifier (`o_xid`).
    pub xid: u64,
    /// Raw `o_type` (type + storage/flag bits).
    pub obj_type_raw: u32,
    /// `o_subtype`.
    pub subtype: u32,
}

impl ObjPhys {
    /// Parse a header from the start of `block`. Bounds-checked; returns `None`
    /// if the slice is too short (never panics).
    #[must_use]
    pub fn parse(_block: &[u8]) -> Option<Self> {
        todo!("P1: bounds-checked decode of the 32-byte obj_phys_t header")
    }

    /// The object type after masking off storage/flag bits
    /// (`o_type & OBJECT_TYPE_MASK`).
    #[must_use]
    pub fn obj_type(&self) -> u16 {
        (self.obj_type_raw & 0x0000_ffff) as u16
    }
}

/// Compute the APFS Fletcher-64 object checksum over `block`, treating the first
/// 8 bytes (the stored `o_cksum`) as zero.
///
/// Apple specifies Fletcher-64; the exact modular arithmetic is taken from the
/// libfsapfs reverse-engineered spec and **must be validated against real APFS
/// object test vectors + apfsck** before being trusted (a wrong implementation
/// would make every block fail verification).
#[must_use]
pub fn fletcher64_checksum(_block: &[u8]) -> u64 {
    todo!("P1: Fletcher-64 with the documented APFS folding; verify vs real objects")
}
