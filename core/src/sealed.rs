//! Sealed / signed system volume: integrity metadata and file-info records —
//! **parse + accessors only** (hash recomputation + seal validation live in the
//! analyzer, `apfs-forensic::sealed`).
//!
//! On a sealed volume (macOS Signed System Volume), an
//! `integrity_meta_phys_t` object (type `OBJECT_TYPE_INTEGRITY_META 0x1e`)
//! anchors a Merkle tree over the volume's content. Apple *APFS Reference*,
//! `integrity_meta_phys_t`: `im_version`, `im_flags`, `im_hash_type`
//! (`apfs_hash_type_t`, e.g. SHA-256), `im_root_hash_offset`, **`im_broken_xid`**
//! (non-zero ⇒ the seal was broken at that transaction), `im_reserved[9]`.
//! Per-file hashes live in `APFS_TYPE_FILE_INFO 13` records (`j_file_info_val_t`)
//! and a file-extent tree (`fext_tree_key_t`/`fext_tree_val_t`, type
//! `OBJECT_TYPE_FEXT_TREE 0x1f`).
//!
//! This module decodes those structures and exposes accessors (root hash, hash
//! type, `im_broken_xid`, per-file hashes). It does **not** recompute or compare
//! hashes — that is a forensic judgment (and the exact canonicalization is the
//! least-documented, highest-FP-risk area), so it lives in the analyzer and is
//! validated only against a real SSV image + apfsck.

/// Parsed integrity metadata.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IntegrityMeta {
    pub version: u32,
    pub flags: u32,
    pub hash_type: u32,
    /// Non-zero ⇒ the seal is recorded as broken at this transaction id.
    pub broken_xid: u64,
}

impl IntegrityMeta {
    /// Parse an `integrity_meta_phys_t`.
    pub fn parse(_block: &[u8]) -> crate::Result<Self> {
        todo!("P8: decode integrity_meta_phys_t (parse only)")
    }
}
