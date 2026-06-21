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
//! is *supplied*, unwraps via a vetted crate (RustCrypto AES/HMAC/PBKDF2,
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
