//! Object map (`omap_phys_t`, type `OBJECT_TYPE_OMAP 0xb`) and virtual-oid
//! resolution.
//!
//! A *virtual* object's oid is not its block address; it is resolved through an
//! object map at a given transaction id. The omap header (Apple *APFS
//! Reference*, `omap_phys_t`) points at a B-tree (`om_tree_oid`) whose keys are
//! `omap_key_t { ok_oid, ok_xid }` (16 bytes) and whose values are
//! `omap_val_t { ov_flags, ov_size, ov_paddr }` (16 bytes). Looking up
//! `(virtual_oid, xid)` yields the physical block address of the object as of
//! that transaction — the mechanism behind both live access and point-in-time
//! snapshot views.
//!
//! `om_flags` (e.g. `OMAP_MANUALLY_MANAGED 0x1`, `OMAP_ENCRYPTING 0x2`,
//! `OMAP_KEYROLLING 0x8`) describe snapshot/encryption state.
//!
//! Field offsets (Apple `omap_phys_t`, little-endian on disk), after the 32-byte
//! `obj_phys_t om_o` header:
//!
//! | off | size | field                  |
//! |-----|------|------------------------|
//! | 32  | 4    | `om_flags`             |
//! | 36  | 4    | `om_snap_count`        |
//! | 40  | 4    | `om_tree_type`         |
//! | 44  | 4    | `om_snapshot_tree_type`|
//! | 48  | 8    | `om_tree_oid`          |
//! | 56  | 8    | `om_snapshot_tree_oid` |
//! | 64  | 8    | `om_most_recent_snap`  |
//! | 72  | 8    | `om_pending_revert_min`|
//! | 80  | 8    | `om_pending_revert_max`|

use crate::object::{fletcher64_checksum, fletcher64_stored, ObjPhys};

/// Object type code `OBJECT_TYPE_OMAP` (Apple): `o_type & 0xffff == 0xb`.
const OBJECT_TYPE_OMAP: u16 = 0xb;

// `omap_phys_t` field offsets after the 32-byte `obj_phys_t om_o` header.
const OFF_OM_FLAGS: usize = 32;
const OFF_OM_TREE_TYPE: usize = 40;
const OFF_OM_TREE_OID: usize = 48;
const OFF_OM_SNAPSHOT_TREE_OID: usize = 56;

/// Minimum readable `omap_phys_t` length: header through `om_tree_oid`.
const OMAP_PHYS_MIN_LEN: usize = OFF_OM_TREE_OID + 8;

/// An object map header (`omap_phys_t`): the entry point into a volume/container
/// object map's backing B-tree.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ObjectMap {
    flags: u32,
    tree_type: u32,
    tree_oid: u64,
    snapshot_tree_oid: u64,
}

impl ObjectMap {
    /// Parse and validate an `omap_phys_t` header from a block.
    ///
    /// Validates magic-by-type (`o_type & 0xffff == OBJECT_TYPE_OMAP`) and the
    /// Fletcher-64 checksum before trusting any field (checksum-before-trust).
    ///
    /// # Errors
    /// [`crate::ApfsError::NoValidSuperblock`]-style failures are not used here;
    /// instead [`crate::ApfsError::UnexpectedObjectType`] is returned for a short
    /// block or a non-omap object (carrying the offending type), and
    /// [`crate::ApfsError::ChecksumMismatch`] for a Fletcher-64 failure.
    pub fn parse(block: &[u8]) -> crate::Result<Self> {
        if block.len() < OMAP_PHYS_MIN_LEN {
            return Err(crate::ApfsError::UnexpectedObjectType {
                structure: "omap_phys",
                expected: u32::from(OBJECT_TYPE_OMAP),
                found: 0,
            });
        }
        // Type gate: the block must be an OMAP object.
        let Some(hdr) = ObjPhys::parse(block) else {
            return Err(crate::ApfsError::UnexpectedObjectType {
                structure: "omap_phys",
                expected: u32::from(OBJECT_TYPE_OMAP),
                found: 0,
            }); // cov:unreachable: len checked >= OMAP_PHYS_MIN_LEN > OBJ_PHYS_LEN
        };
        if hdr.obj_type() != OBJECT_TYPE_OMAP {
            return Err(crate::ApfsError::UnexpectedObjectType {
                structure: "omap_phys",
                expected: u32::from(OBJECT_TYPE_OMAP),
                found: hdr.obj_type_raw,
            });
        }
        // Checksum gate before trusting the tree oids.
        let stored = fletcher64_stored(block);
        let computed = fletcher64_checksum(block);
        if stored != computed {
            return Err(crate::ApfsError::ChecksumMismatch {
                block: hdr.oid,
                stored,
                computed,
            });
        }

        Ok(Self {
            flags: crate::bytes::le_u32(block, OFF_OM_FLAGS),
            tree_type: crate::bytes::le_u32(block, OFF_OM_TREE_TYPE),
            tree_oid: crate::bytes::le_u64(block, OFF_OM_TREE_OID),
            snapshot_tree_oid: crate::bytes::le_u64(block, OFF_OM_SNAPSHOT_TREE_OID),
        })
    }

    /// `om_tree_oid` — the oid of the B-tree backing this object map. For a
    /// container omap the tree is stored *physically* (`om_tree_type` carries the
    /// physical storage flag), so this oid is also the tree root's block address.
    #[must_use]
    pub fn tree_oid(&self) -> u64 {
        self.tree_oid
    }

    /// `om_tree_type` (storage flags in the high bits | object type in the low).
    #[must_use]
    pub fn tree_type(&self) -> u32 {
        self.tree_type
    }

    /// `om_flags` (`OMAP_MANUALLY_MANAGED 0x1`, `OMAP_ENCRYPTING 0x2`, …).
    #[must_use]
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// `om_snapshot_tree_oid` — `0` when the omap has no snapshot tree.
    #[must_use]
    pub fn snapshot_tree_oid(&self) -> u64 {
        self.snapshot_tree_oid
    }
}
