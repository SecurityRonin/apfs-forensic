//! Inode records (`APFS_TYPE_INODE 3`, value `j_inode_val_t`).
//!
//! Apple *APFS Reference*, `j_inode_val_t`: `parent_id`, `private_id` (the
//! data-stream object id), four timestamps `create_time` / `mod_time` /
//! `change_time` / `access_time`, `internal_flags`, a `nchildren`/`nlink` union,
//! then xfields. **Timestamps are `uint64_t` nanoseconds since 1970-01-01 00:00
//! UTC** (disregarding leap seconds); zero is a contextual lead, not a
//! spec-defined "unset" sentinel. The filename lives in an `INO_EXT_TYPE_NAME`
//! xfield, the data stream in an `INO_EXT_TYPE_DSTREAM` xfield.

use chrono::{DateTime, Utc};

/// A parsed inode.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Inode {
    pub oid: u64,
    pub parent_id: u64,
    pub private_id: u64,
    pub create_time: u64,
    pub mod_time: u64,
    pub change_time: u64,
    pub access_time: u64,
    pub internal_flags: u64,
    pub nlink_or_nchildren: i32,
    pub name: Option<String>,
}

impl Inode {
    /// Parse a `j_inode_val_t` value (+ xfields) for `oid`.
    pub fn parse(_oid: u64, _value: &[u8]) -> crate::Result<Self> {
        todo!("P3: decode fixed inode fields + xfields (name, dstream)")
    }

    /// `create_time` as a UTC timestamp.
    #[must_use]
    pub fn created(&self) -> Option<DateTime<Utc>> {
        ns_to_datetime(self.create_time)
    }
}

/// Convert APFS nanoseconds-since-epoch to a UTC datetime (bounds-checked).
#[must_use]
pub fn ns_to_datetime(_ns: u64) -> Option<DateTime<Utc>> {
    todo!("P3: chrono from nanoseconds, range-checked")
}
