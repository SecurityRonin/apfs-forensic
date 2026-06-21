//! Encryption-state surfacing (no key cracking).
//!
//! `APFS-ENCRYPTION-LOCKED` (Info), `APFS-ENCRYPTION-STATE` (Info — reports the
//! concrete observed keybag/crypto-state fields verbatim; does NOT classify
//! software-vs-hardware, which is not safely derivable from on-disk structures),
//! `APFS-ENCRYPTION-KEYBAG-ANOMALY` (Medium — carries the raw offending tag
//! value + offset).

use crate::AnomalyKind;

/// Audit a volume's encryption state.
#[must_use]
pub fn audit(_state: &apfs_core::encryption::EncryptionState) -> Vec<AnomalyKind> {
    todo!("P9: report locked state + raw keybag fields; flag malformed tags with the value")
}
