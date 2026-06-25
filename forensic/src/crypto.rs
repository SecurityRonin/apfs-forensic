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
pub fn audit(state: &apfs_core::encryption::EncryptionState) -> Vec<AnomalyKind> {
    let detail = format!(
        "encrypted={}, tags={:?}, passphrase_hint={}",
        state.encrypted, state.tags_present, state.has_passphrase_hint
    );
    crypto_anomalies(state.encrypted, &detail, &state.unknown_tags)
}

/// Pure encryption-state audit logic (Humble Object: testable without
/// constructing an `EncryptionState`). Emits an Info `ENCRYPTION-LOCKED` when the
/// volume is encrypted (no key is ever available — state surfacing only), an
/// Info `ENCRYPTION-STATE` reporting the raw observed fields, and a Medium
/// `ENCRYPTION-KEYBAG-ANOMALY` per unrecognised keybag tag carrying its raw value
/// and offset (never classifies software-vs-hardware).
fn crypto_anomalies(
    _encrypted: bool,
    _detail: &str,
    _unknown_tags: &[(u16, u64)],
) -> Vec<AnomalyKind> {
    Vec::new() // RED stub
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(v: &[AnomalyKind]) -> Vec<&'static str> {
        v.iter().map(AnomalyKind::code).collect()
    }

    #[test]
    fn unencrypted_clean_keybag_has_no_findings() {
        assert!(crypto_anomalies(false, "encrypted=false", &[]).is_empty());
    }

    #[test]
    fn encrypted_volume_is_locked_and_reported() {
        let v = crypto_anomalies(true, "encrypted=true, tags=[VolumeKey]", &[]);
        let c = codes(&v);
        assert!(c.contains(&"APFS-ENCRYPTION-LOCKED"));
        assert!(c.contains(&"APFS-ENCRYPTION-STATE"));
    }

    #[test]
    fn unknown_tag_yields_keybag_anomaly_with_value() {
        let v = crypto_anomalies(true, "d", &[(0x55, 16)]);
        let anomaly = v
            .iter()
            .find(|a| a.code() == "APFS-ENCRYPTION-KEYBAG-ANOMALY")
            .expect("keybag anomaly present");
        // The note must surface the raw tag value + offset.
        let note = forensicnomicon::report::Observation::note(anomaly);
        assert!(note.contains("0x55") && note.contains("16"), "{note}");
    }
}
