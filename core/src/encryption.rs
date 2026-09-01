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

impl KeybagTag {
    /// Map a raw `ke_tag` value to a known tag, or [`KeybagTag::Unknown`].
    #[must_use]
    pub fn from_u16(tag: u16) -> Self {
        match tag {
            0x01 => Self::WrappingKey,
            0x02 => Self::VolumeKey,
            0x03 => Self::VolumeUnlockRecords,
            0x04 => Self::VolumePassphraseHint,
            0xf8 => Self::UserPayload,
            _ => Self::Unknown,
        }
    }
}

/// Observed encryption state of a volume (no secrets).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EncryptionState {
    pub encrypted: bool,
    pub tags_present: Vec<KeybagTag>,
    pub has_passphrase_hint: bool,
    /// Raw `(ke_tag, entry offset)` pairs for keybag entries whose tag is not a
    /// recognised `KB_TAG_*` value — surfaced so an audit can report the
    /// offending value + location (show-the-value rule), not just "unknown".
    pub unknown_tags: Vec<(u16, u64)>,
}

// `kb_locker` header field offsets, then 16-byte-aligned `keybag_entry_t`s.
const KL_NKEYS: usize = 2; // u16
const KL_ENTRIES_OFF: usize = 16; // entries begin after the 16-byte header
const KE_TAG: usize = 16; // u16 within an entry
const KE_KEYLEN: usize = 18; // u16 within an entry
const KE_HEADER_LEN: usize = 24; // uuid(16) + tag(2) + keylen(2) + pad(4)
/// Cap on `kl_nkeys` (a hostile blob must not drive an unbounded loop).
const MAX_KEYBAG_ENTRIES: usize = 4096;

/// Parse a container/volume keybag (`kb_locker`) into observed state — which
/// tags are present, whether a passphrase hint exists, and whether key material
/// is present — **without** unwrapping any key.
///
/// # Errors
/// [`crate::ApfsError::Io`] never (in-memory); returns `Ok` with whatever the
/// blob structurally yields. A malformed entry stops the walk early rather than
/// over-reading.
pub fn read_keybag(data: &[u8]) -> crate::Result<EncryptionState> {
    let nkeys = (crate::bytes::le_u16(data, KL_NKEYS) as usize).min(MAX_KEYBAG_ENTRIES);
    let mut tags_present = Vec::new();
    let mut unknown_tags = Vec::new();
    let mut off = KL_ENTRIES_OFF;
    for _ in 0..nkeys {
        // Stop if the entry header would run past the blob (never over-read).
        if off + KE_HEADER_LEN > data.len() {
            break;
        }
        let raw_tag = crate::bytes::le_u16(data, off + KE_TAG);
        let tag = KeybagTag::from_u16(raw_tag);
        let keylen = crate::bytes::le_u16(data, off + KE_KEYLEN) as usize;
        if tag == KeybagTag::Unknown {
            unknown_tags.push((raw_tag, off as u64));
        }
        if !tags_present.contains(&tag) {
            tags_present.push(tag);
        }
        // Advance by the 16-byte-aligned entry size.
        let entry_len = (KE_HEADER_LEN + keylen + 15) & !15;
        off += entry_len.max(16);
    }
    let has_passphrase_hint = tags_present.contains(&KeybagTag::VolumePassphraseHint);
    // "Encrypted" = actual key material is present (a wrapping key, a wrapped
    // volume key, or the volume-keybag unlock records).
    let encrypted = tags_present.iter().any(|t| {
        matches!(
            t,
            KeybagTag::WrappingKey | KeybagTag::VolumeKey | KeybagTag::VolumeUnlockRecords
        )
    });
    Ok(EncryptionState {
        encrypted,
        tags_present,
        has_passphrase_hint,
        unknown_tags,
    })
}

/// The three inputs the FileVault unwrap chain needs, read from a wrapped-KEK
/// object in a volume keybag entry.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WrappedKek {
    /// RFC 3394 wrapped key encryption key — always 40 bytes (32-byte key + the
    /// 8-byte integrity check AES-KW prepends).
    pub wrapped_key: Vec<u8>,
    /// PBKDF2 iteration count used to derive the unwrapping key from a password.
    pub iterations: u32,
    /// PBKDF2 salt — always 16 bytes.
    pub salt: Vec<u8>,
}

/// Parse a wrapped-KEK object (BER TLV) into its unwrap inputs.
///
/// Framing is BER definite-length, as the libfsapfs reference reads it: a tag
/// byte, then a length byte that is either the length itself (high bit clear),
/// or `0x81`/`0x82` announcing a 1- or 2-byte length that follows. Any other
/// leading length byte is rejected rather than guessed at.
///
/// Unrecognised tags are skipped, not fatal: the format carries fields this
/// chain does not need (`0x81` volume GUID, `0x82` metadata) and may gain more.
///
/// # Errors
/// [`crate::ApfsError::FieldOutOfRange`] when the blob is truncated, a length is
/// unsupported, or a field has a size the format does not permit. Sizes are
/// invariants: a wrong-sized wrapped key or salt cannot yield a correct key, and
/// unwrapping it would produce plausible garbage rather than an error.
pub fn parse_wrapped_kek(data: &[u8]) -> crate::Result<WrappedKek> {
    const TAG_WRAPPED_KEK: u8 = 0x83;
    const TAG_ITERATIONS: u8 = 0x84;
    const TAG_SALT: u8 = 0x85;
    /// RFC 3394 output for a 256-bit key: 32-byte key + 8-byte integrity check.
    const WRAPPED_KEK_LEN: usize = 40;
    const SALT_LEN: usize = 16;

    // Reuse the crate's existing error vocabulary rather than inventing one, and
    // carry the offending value: "wrong size" without the size is a prompt to go
    // and look, not a diagnosis.
    let bad = |field: &'static str, value: u64, cap: u64| crate::ApfsError::FieldOutOfRange {
        structure: "wrapped_kek_object",
        field,
        value,
        cap,
    };

    let mut wrapped_key: Option<Vec<u8>> = None;
    let mut iterations: Option<u32> = None;
    let mut salt: Option<Vec<u8>> = None;

    let mut off = 0usize;
    while off < data.len() {
        let tag = *data
            .get(off)
            .ok_or_else(|| bad("tag", off as u64, data.len() as u64))?;
        off += 1;
        let first = *data
            .get(off)
            .ok_or_else(|| bad("length", off as u64, data.len() as u64))?;
        off += 1;

        let len = if first & 0x80 == 0 {
            first as usize
        } else if first == 0x81 {
            let b = *data
                .get(off)
                .ok_or_else(|| bad("length_1byte", off as u64, data.len() as u64))?;
            off += 1;
            b as usize
        } else if first == 0x82 {
            let hi = *data
                .get(off)
                .ok_or_else(|| bad("length_2byte", off as u64, data.len() as u64))?;
            let lo = *data
                .get(off + 1)
                .ok_or_else(|| bad("length_2byte", off as u64, data.len() as u64))?;
            off += 2;
            ((hi as usize) << 8) | lo as usize
        } else {
            return Err(bad("ber_length_form", u64::from(first), 0x82));
        };

        let end = off
            .checked_add(len)
            .ok_or_else(|| bad("value_length", len as u64, data.len() as u64))?;
        let value = data
            .get(off..end)
            .ok_or_else(|| bad("value_end", end as u64, data.len() as u64))?;
        off = end;

        match tag {
            TAG_WRAPPED_KEK => {
                if value.len() != WRAPPED_KEK_LEN {
                    return Err(bad(
                        "wrapped_kek_len",
                        value.len() as u64,
                        WRAPPED_KEK_LEN as u64,
                    ));
                }
                wrapped_key = Some(value.to_vec());
            }
            TAG_ITERATIONS => {
                if value.is_empty() || value.len() > 8 {
                    return Err(bad("iterations_len", value.len() as u64, 8));
                }
                // Big-endian, minimal width. Saturate rather than wrap: a hostile
                // count must not silently become a small, fast one.
                let mut n: u64 = 0;
                for b in value {
                    n = (n << 8) | u64::from(*b);
                }
                iterations = Some(u32::try_from(n).unwrap_or(u32::MAX));
            }
            TAG_SALT => {
                if value.len() != SALT_LEN {
                    return Err(bad("salt_len", value.len() as u64, SALT_LEN as u64));
                }
                salt = Some(value.to_vec());
            }
            _ => {}
        }
    }

    Ok(WrappedKek {
        wrapped_key: wrapped_key.ok_or_else(|| bad("wrapped_kek_tag_0x83", 0, 1))?,
        iterations: iterations.ok_or_else(|| bad("iterations_tag_0x84", 0, 1))?,
        salt: salt.ok_or_else(|| bad("salt_tag_0x85", 0, 1))?,
    })
}

/// Unwrap an RFC 3394 AES-KW wrapped key.
///
/// # Errors
/// [`crate::ApfsError::FieldOutOfRange`] if the input is not a valid wrapped key
/// or the integrity check fails (i.e. the KEK is wrong).
pub fn aes_key_unwrap(_kek: &[u8; 32], _wrapped: &[u8; 40]) -> crate::Result<Vec<u8>> {
    // RED stub: structurally valid, wrong value, always Ok — so the vector test
    // fails on its assertion and the wrong-KEK test fails by NOT erroring.
    Ok(vec![0u8; 32])
}

/// PBKDF2-HMAC-SHA1, used only to check the plumbing against RFC 6070's vector.
#[cfg(test)]
#[must_use]
pub fn pbkdf2_sha1_for_test(_pw: &[u8], _salt: &[u8], _iters: u32, out_len: usize) -> Vec<u8> {
    vec![0u8; out_len] // RED stub
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
    fn from_u16_maps_every_known_tag() {
        // Each documented KB_TAG_* value decodes to its named variant; a wrapping
        // key, unlock records, or user payload all round-trip through from_u16.
        assert_eq!(KeybagTag::from_u16(0x01), KeybagTag::WrappingKey);
        assert_eq!(KeybagTag::from_u16(0x02), KeybagTag::VolumeKey);
        assert_eq!(KeybagTag::from_u16(0x03), KeybagTag::VolumeUnlockRecords);
        assert_eq!(KeybagTag::from_u16(0x04), KeybagTag::VolumePassphraseHint);
        assert_eq!(KeybagTag::from_u16(0xf8), KeybagTag::UserPayload);
        assert_eq!(KeybagTag::from_u16(0x99), KeybagTag::Unknown);
    }

    #[test]
    fn wrapping_key_and_unlock_records_are_encrypted() {
        // A volume keybag with a wrapping key (0x01) and unlock records (0x03) is
        // encrypted, and both named tags are surfaced.
        let kb = keybag(&[(0x01, 32), (0x03, 16)]);
        let st = read_keybag(&kb).expect("parse keybag");
        assert!(st.encrypted, "wrapping-key / unlock-records ⇒ encrypted");
        assert!(st.tags_present.contains(&KeybagTag::WrappingKey));
        assert!(st.tags_present.contains(&KeybagTag::VolumeUnlockRecords));
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
    fn unknown_tag_maps_to_unknown_and_records_raw_value() {
        // A reserved/unexpected tag must decode as Unknown (never panic) and its
        // raw value + offset must be retained for the show-the-value rule.
        let kb = keybag(&[(0x55, 4)]);
        let st = read_keybag(&kb).expect("parse keybag");
        assert!(st.tags_present.contains(&KeybagTag::Unknown));
        assert_eq!(st.unknown_tags, vec![(0x55u16, 16u64)]);
    }

    #[test]
    fn header_claiming_more_entries_than_the_blob_stops_early() {
        // kl_nkeys says 4 entries but the blob is only the 16-byte header + 8
        // bytes: the walk must break at the first entry that would over-read,
        // never panic or over-read (bounds-safe against a lying count).
        let mut data = vec![0u8; 24];
        data[0..2].copy_from_slice(&1u16.to_le_bytes()); // kl_version
        data[2..4].copy_from_slice(&4u16.to_le_bytes()); // kl_nkeys (lies)
        let st = read_keybag(&data).expect("parse truncated keybag");
        assert!(st.tags_present.is_empty(), "no entry fits → nothing parsed");
    }

    /// RED: a wrapped-KEK object is a BER TLV blob carrying the three inputs the
    /// unwrap chain needs — the 40-byte wrapped KEK (`0x83`), the PBKDF2
    /// iteration count (`0x84`) and the 16-byte salt (`0x85`). Sizes per the
    /// libfsapfs reference: 40 is exactly RFC 3394 output for a 256-bit key.
    ///
    /// Asserts the extracted VALUES, not merely that parsing returned Ok — a
    /// parser that yielded zeros would otherwise pass.
    #[test]
    fn wrapped_kek_object_yields_salt_iterations_and_wrapped_key() {
        let mut blob = Vec::new();
        // 0x82 metadata (8 bytes) — present in real objects, must be skipped
        blob.push(0x82u8);
        blob.push(8u8);
        blob.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0]);
        // 0x83 wrapped KEK, exactly 40 bytes, long-form length (0x81 + len)
        blob.push(0x83u8);
        blob.push(0x81u8);
        blob.push(40u8);
        let wrapped: Vec<u8> = (0..40u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        blob.extend_from_slice(&wrapped);
        // 0x84 iteration count, big-endian, minimal width
        blob.push(0x84u8);
        blob.push(3u8);
        blob.extend_from_slice(&[0x01, 0xE8, 0x48]); // 125_000
                                                     // 0x85 salt, exactly 16 bytes
        blob.push(0x85u8);
        blob.push(16u8);
        let salt: Vec<u8> = (0..16u8).map(|i| i ^ 0x5A).collect();
        blob.extend_from_slice(&salt);

        let kek = parse_wrapped_kek(&blob).expect("a well-formed wrapped-KEK object must parse");
        assert_eq!(
            kek.wrapped_key.as_slice(),
            wrapped.as_slice(),
            "wrapped KEK bytes"
        );
        assert_eq!(kek.iterations, 125_000, "PBKDF2 iteration count");
        assert_eq!(kek.salt.as_slice(), salt.as_slice(), "PBKDF2 salt");
    }

    /// Sizes are invariants, not suggestions. A hostile blob declaring a short
    /// wrapped key must be REFUSED: a 32-byte value cannot be RFC 3394 output,
    /// and unwrapping it would yield plausible garbage rather than an error.
    ///
    /// The blob is otherwise COMPLETE — valid iterations and salt — so the wrong
    /// size is the only defect. An earlier version omitted those fields and
    /// passed even with the size check deleted, because it was erroring on the
    /// missing iteration count instead. A rejection test must fail for the one
    /// reason it names.
    #[test]
    fn wrapped_kek_object_rejects_a_wrong_sized_wrapped_key() {
        let mut blob = Vec::new();
        blob.push(0x83u8);
        blob.push(32u8); // WRONG: must be 40
        blob.extend_from_slice(&[0u8; 32]);
        blob.push(0x84u8);
        blob.push(2u8);
        blob.extend_from_slice(&[0x27, 0x10]); // 10_000 — valid
        blob.push(0x85u8);
        blob.push(16u8);
        blob.extend_from_slice(&[0u8; 16]); // valid

        let err = parse_wrapped_kek(&blob)
            .expect_err("a 32-byte wrapped key must be rejected; only 40 is valid");
        // Assert on the FIELD, so passing for some unrelated reason is not enough.
        let msg = format!("{err}");
        assert!(
            msg.contains("wrapped_kek_len"),
            "must be rejected for the wrapped-key SIZE, got: {msg}"
        );
    }

    /// RED (Tier-1): AES key unwrap must match RFC 3394's own published test
    /// vector. Third-party artifact AND answer key, so this is not
    /// self-validating — section 4.6, "Wrap 256 bits of Key Data with a 256-bit
    /// KEK".
    #[test]
    fn aes_key_unwrap_matches_rfc3394_vector() {
        let kek: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let wrapped: [u8; 40] = [
            0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87,
            0xF8, 0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7,
            0x1A, 0x99, 0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
        ];
        let expected: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let got = aes_key_unwrap(&kek, &wrapped).expect("RFC 3394 vector must unwrap");
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "RFC 3394 s4.6 unwrapped key"
        );
    }

    /// RED: the integrity check is the whole point of AES-KW. A wrong KEK must be
    /// REFUSED, not returned as garbage — otherwise a wrong password silently
    /// yields a wrong key and every later failure is misattributed.
    #[test]
    fn aes_key_unwrap_rejects_a_wrong_kek() {
        let wrong = [0xAAu8; 32];
        let wrapped: [u8; 40] = [
            0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87,
            0xF8, 0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7,
            0x1A, 0x99, 0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
        ];
        assert!(
            aes_key_unwrap(&wrong, &wrapped).is_err(),
            "a wrong KEK must fail the AES-KW integrity check, never return bytes"
        );
    }

    /// RED (Tier-1): password stretching must match RFC 6070's published
    /// PBKDF2-HMAC-SHA1 vector, confirming iteration/salt handling is wired the
    /// standard way round. APFS uses SHA-256, but the vector proves the plumbing.
    #[test]
    fn pbkdf2_matches_rfc6070_vector() {
        let out = pbkdf2_sha1_for_test(b"password", b"salt", 2, 20);
        let expected: [u8; 20] = [
            0xEA, 0x6C, 0x01, 0x4D, 0xC7, 0x2D, 0x6F, 0x8C, 0xCD, 0x1E, 0xD9, 0x2A, 0xCE, 0x1D,
            0x41, 0xF0, 0xD8, 0xDE, 0x89, 0x57,
        ];
        assert_eq!(out.as_slice(), expected.as_slice(), "RFC 6070 c=2 vector");
    }
}
