//! Fusion (SSD + HDD) support.
//!
//! A Fusion container spans two devices: a fast tier (SSD) and a slow tier
//! (HDD). The fusion middle tree (`OBJECT_TYPE_FUSION_MIDDLE_TREE 0x15`) maps
//! logical addresses across tiers, and a write-back cache
//! (`OBJECT_TYPE_NX_FUSION_WBC 0x16` / `..._WBC_LIST 0x17`) buffers writes. The
//! high bit of a Fusion physical address selects the tier.
//!
//! **Ordering note (Codex):** Fusion changes physical-address resolution, so the
//! reader cannot correctly read a Fusion image's blocks without at least minimal
//! tier-aware translation. P1/P2 must therefore either implement the minimal
//! address split **or** detect a Fusion container and fail loud with
//! [`crate::ApfsError::UnsupportedFusion`] — never silently mis-read addresses.

/// Detect whether a container is a Fusion container, from the
/// `NX_INCOMPAT_FUSION` bit in the NXSB `nx_incompatible_features` word.
#[must_use]
pub fn is_fusion(superblock: &crate::container::NxSuperblock) -> bool {
    superblock.incompatible_features & crate::container::NX_INCOMPAT_FUSION != 0
}

/// Translate a (possibly tier-flagged) Fusion physical address to a device +
/// block. Until full support lands, callers detecting Fusion must return
/// [`crate::ApfsError::UnsupportedFusion`].
pub fn translate_address(_paddr: u64) -> crate::Result<u64> {
    todo!("P8: tier split on the high address bit; full middle-tree mapping")
}
