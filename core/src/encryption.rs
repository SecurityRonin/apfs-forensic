//! Encryption: keybag parsing and crypto-state records — **state surfacing
//! only** (no key cracking, no hand-rolled crypto).
//!
//! An encrypted container/volume stores wrapped keys in keybags. The container
//! keybag (referenced from `nx_keylocker`) holds, per volume,
//! `KB_TAG_VOLUME_KEY 0x02` (a wrapped volume encryption key / KEK packed
//! object) and `KB_TAG_VOLUME_UNLOCK_RECORDS 0x03` (the volume keybag extent);
//! the volume keybag holds `KB_TAG_WRAPPING_KEY 0x01` and
//! `KB_TAG_VOLUME_PASSPHRASE_HINT 0x04`. Keybag tag values (libfsapfs):
//! `KB_TAG_UNKNOWN 0x00`, `KB_TAG_WRAPPING_KEY 0x01`, `KB_TAG_VOLUME_KEY 0x02`,
//! `KB_TAG_VOLUME_UNLOCK_RECORDS 0x03`, `KB_TAG_VOLUME_PASSPHRASE_HINT 0x04`,
//! `KB_TAG_USER_PAYLOAD 0xf8`.
//!
//! Per-file crypto state is `APFS_TYPE_CRYPTO_STATE 7` (`j_crypto_val_t` with a
//! `wrapped_meta_crypto_state_t`). This module **reports** what is present —
//! locked/unlocked, which tags, hint presence — and, only when a key/passphrase
//! is *supplied*, unwraps via a vetted crate (`RustCrypto` AES/HMAC/PBKDF2,
//! AES-XTS). With no key it **refuses** to return plaintext; it never fabricates.

/// Keybag tag values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeybagTag {
    Unknown = 0x00,
    WrappingKey = 0x01,
    VolumeKey = 0x02,
    VolumeUnlockRecords = 0x03,
    VolumePassphraseHint = 0x04,
    UserPayload = 0xf8,
}

/// Observed encryption state of a volume (no secrets).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EncryptionState {
    pub encrypted: bool,
    pub tags_present: Vec<KeybagTag>,
    pub has_passphrase_hint: bool,
}

/// Parse a container/volume keybag into observed state.
pub fn read_keybag(_data: &[u8]) -> crate::Result<EncryptionState> {
    todo!("P7: parse keybag entries by tag; report state, never derive keys")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `kb_locker` keybag blob: 16-byte header (`kl_version`@0,
    /// `kl_nkeys`@2, `kl_nbytes`@4, pad), then `keybag_entry_t` entries
    /// (`ke_uuid`@0[16], `ke_tag`@16, `ke_keylen`@18, pad[4], `ke_keydata`@24),
    /// each 16-byte aligned (libfsapfs layout).
    fn keybag(entries: &[(u16, usize)]) -> Vec<u8> {
        let mut data = vec![0u8; 16];
        data[0..2].copy_from_slice(&1u16.to_le_bytes()); // kl_version
        data[2..4].copy_from_slice(&(entries.len() as u16).to_le_bytes()); // kl_nkeys
        for &(tag, keylen) in entries {
            let mut e = vec![0u8; 24 + keylen];
            e[16..18].copy_from_slice(&tag.to_le_bytes()); // ke_tag
            e[18..20].copy_from_slice(&(keylen as u16).to_le_bytes()); // ke_keylen
            let padded = (e.len() + 15) & !15; // 16-byte align
            e.resize(padded, 0);
            data.extend_from_slice(&e);
        }
        let nbytes = data.len() as u32;
        data[4..8].copy_from_slice(&nbytes.to_le_bytes()); // kl_nbytes
        data
    }

    #[test]
    fn reads_volume_key_and_hint_tags() {
        // A volume keybag with a wrapped volume key and a passphrase hint.
        let kb = keybag(&[(0x02, 32), (0x04, 8)]);
        let st = read_keybag(&kb).expect("parse keybag");
        assert!(st.encrypted, "a keybag with a volume key is encrypted");
        assert!(st.tags_present.contains(&KeybagTag::VolumeKey));
        assert!(st.tags_present.contains(&KeybagTag::VolumePassphraseHint));
        assert!(st.has_passphrase_hint);
    }

    #[test]
    fn empty_keybag_reports_not_encrypted() {
        let kb = keybag(&[]);
        let st = read_keybag(&kb).expect("parse empty keybag");
        assert!(!st.encrypted);
        assert!(st.tags_present.is_empty());
        assert!(!st.has_passphrase_hint);
    }

    #[test]
    fn unknown_tag_maps_to_unknown_not_panic() {
        // A reserved/unexpected tag must decode as Unknown, never panic.
        let kb = keybag(&[(0x55, 4)]);
        let st = read_keybag(&kb).expect("parse keybag");
        assert!(st.tags_present.contains(&KeybagTag::Unknown));
    }
}
