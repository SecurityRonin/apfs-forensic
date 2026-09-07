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
// A keybag block is an APFS OBJECT: a 32-byte obj_phys header (cksum, oid, xid,
// type, subtype) precedes the kb_locker. Confirmed two ways -- the magic sits in
// o_type at +24 ("keys" for a container bag, "recs" for a volume bag) in the real
// fixture, and apfs-fuse's media_keybag_t carries an mk_obj member whose
// mk_obj.o_type it validates.
//
// Omitting this made kl_nkeys read as 12824 (garbage); entry scanning resynced by
// luck, which is why it appeared to work.
const OBJ_PHYS_LEN: usize = 32;
const KL_NKEYS: usize = OBJ_PHYS_LEN + 2; // kl_nkeys, u16
const KL_ENTRIES_OFF: usize = OBJ_PHYS_LEN + 16; // entries follow the 16-byte kb_locker
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
/// The 8-byte integrity check AES-KW carries is what makes a wrong password
/// *detectable*: it fails here rather than silently yielding a wrong key that
/// only shows up later as an unreadable volume.
///
/// # Errors
/// [`crate::ApfsError::FieldOutOfRange`] if the integrity check fails — which in
/// practice means the derived key, and therefore the password, is wrong.
pub fn aes_key_unwrap(kek: &[u8; 32], wrapped: &[u8; 40]) -> crate::Result<Vec<u8>> {
    use aes_kw::KekAes256;
    let kek = KekAes256::from(*kek);
    kek.unwrap_vec(wrapped)
        .map_err(|_| crate::ApfsError::FieldOutOfRange {
            structure: "aes_key_wrap",
            field: "integrity_check",
            value: 0,
            cap: 1,
        })
}

/// PBKDF2-HMAC-SHA256 — the APFS password-stretching step.
#[must_use]
pub fn derive_key_from_password(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Vec<u8> {
    use hmac::Hmac;
    use sha2::Sha256;

    let mut out = vec![0u8; out_len];
    // Iterations come from the volume and are attacker-influenced; a zero count
    // would make derivation instant, so floor it at 1 rather than trusting it.
    let iters = iterations.max(1);
    // Same call shape filevault-forensic uses against a real FVDE volume.
    // The only failure mode is an invalid output length, which cannot happen for
    // a Vec we just sized — but it is handled rather than unwrapped, because the
    // fleet lints deny unwrap/expect in production for exactly this reason.
    if pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, iters, &mut out).is_err() {
        return Vec::new();
    }
    out
}

/// Walk a BER definite-length TLV blob, returning the value for `want_tag`.
///
/// Shared by every packed object in a keybag, so a fix to the framing reaches
/// all of them rather than only the copy that was noticed.
fn ber_find(data: &[u8], want_tag: u8) -> Option<&[u8]> {
    let mut off = 0usize;
    while off + 2 <= data.len() {
        let tag = *data.get(off)?;
        let first = *data.get(off + 1)?;
        off += 2;
        let len = if first & 0x80 == 0 {
            first as usize
        } else if first == 0x81 {
            let b = *data.get(off)?;
            off += 1;
            b as usize
        } else if first == 0x82 {
            let hi = *data.get(off)?;
            let lo = *data.get(off + 1)?;
            off += 2;
            ((hi as usize) << 8) | lo as usize
        } else {
            return None;
        };
        let end = off.checked_add(len)?;
        let value = data.get(off..end)?;
        if tag == want_tag {
            return Some(value);
        }
        off = end;
    }
    None
}

/// Offsets into `nx_superblock_t`, from the libfsapfs reference structure.
const NX_BLOCK_SIZE: usize = 0x024;
const NX_CONTAINER_UUID: usize = 0x048;
const NX_KEYBAG_BLOCK: usize = 0x510;
const NX_KEYBAG_BLOCKS: usize = 0x518;
/// XTS sector size APFS uses for the keybag.
const KEYBAG_SECTOR: usize = 512;

/// Decrypt the container keybag referenced by the container superblock's
/// `nx_keylocker`.
///
/// The keybag is AES-128-XTS encrypted with the container UUID as BOTH XTS
/// keys. That UUID sits in plaintext in the superblock, so this layer is
/// obfuscation rather than protection and needs no password — which is why
/// container information is readable from a locked volume. The password only
/// enters later, when unwrapping the KEK.
///
/// Reads the superblock at block 0. A container also keeps newer superblocks in
/// its checkpoint descriptor area; selecting the highest-xid one is a separate
/// concern and not needed to reach the keybag.
///
/// # Errors
/// [`crate::ApfsError::FieldOutOfRange`] if the superblock magic is absent or
/// the keylocker extent falls outside the image.
pub fn decrypt_container_keybag(image: &[u8]) -> crate::Result<Vec<u8>> {
    let uuid: [u8; 16] = image
        .get(NX_CONTAINER_UUID..NX_CONTAINER_UUID + 16)
        .and_then(|s| s.try_into().ok())
        .ok_or(crate::ApfsError::FieldOutOfRange {
            structure: "nx_superblock",
            field: "container_uuid",
            value: image.len() as u64,
            cap: (NX_CONTAINER_UUID + 16) as u64,
        })?;
    decrypt_container_keybag_with_uuid(image, &uuid)
}

/// As [`decrypt_container_keybag`] but with an explicit key, so a test can prove
/// a WRONG key fails to produce a parseable keybag.
///
/// # Errors
/// Same as [`decrypt_container_keybag`].
pub fn decrypt_container_keybag_with_uuid(image: &[u8], uuid: &[u8; 16]) -> crate::Result<Vec<u8>> {
    let bad = |field: &'static str, value: u64, cap: u64| crate::ApfsError::FieldOutOfRange {
        structure: "nx_keylocker",
        field,
        value,
        cap,
    };

    if image.get(32..36) != Some(b"NXSB") {
        return Err(bad("magic", 0, 1));
    }
    let block_size = crate::bytes::le_u32(image, NX_BLOCK_SIZE) as usize;
    if block_size == 0 || block_size % KEYBAG_SECTOR != 0 {
        return Err(bad("block_size", block_size as u64, KEYBAG_SECTOR as u64));
    }
    let paddr = crate::bytes::le_u64(image, NX_KEYBAG_BLOCK) as usize;
    let blocks = crate::bytes::le_u64(image, NX_KEYBAG_BLOCKS) as usize;
    if paddr == 0 || blocks == 0 {
        return Err(bad("keylocker_extent", paddr as u64, blocks as u64));
    }

    let start = paddr
        .checked_mul(block_size)
        .ok_or_else(|| bad("keybag_offset", paddr as u64, block_size as u64))?;
    let len = blocks
        .checked_mul(block_size)
        .ok_or_else(|| bad("keybag_length", blocks as u64, block_size as u64))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| bad("keybag_end", start as u64, len as u64))?;
    let ct = image
        .get(start..end)
        .ok_or_else(|| bad("keybag_past_image", end as u64, image.len() as u64))?;

    // One implementation of the XTS step, shared with the ranged entry point:
    // two copies of a tweak calculation is two places for an offset bug to
    // diverge, and the ranged path is the one real evidence goes through.
    // Tweak is the absolute sector index, matching how the data was written.
    Ok(decrypt_keybag_area(ct, uuid, start / KEYBAG_SECTOR))
}

/// Where a volume's unlock material lives, read from the container keybag.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VolumeRecords {
    /// RFC 3394 wrapped volume encryption key (40 bytes), from `KB_TAG_VOLUME_KEY`.
    pub wrapped_vek: Vec<u8>,
    /// Physical block address of the volume keybag, from `KB_TAG_VOLUME_UNLOCK_RECORDS`.
    pub volume_keybag_block: u64,
    /// Length of the volume keybag in blocks.
    pub volume_keybag_blocks: u64,
}

/// Find a volume's records in a DECRYPTED container keybag, by volume UUID.
///
/// Each entry carries the UUID it belongs to, so a multi-volume container keeps
/// key material separate. Matching on that UUID is what stops one volume's keys
/// being handed out for another, which would decrypt to garbage and read as
/// corruption rather than as the lookup error it is.
///
/// # Errors
/// [`crate::ApfsError::FieldOutOfRange`] if the volume is absent, or an entry
/// has a size the format does not permit.
pub fn volume_records(keybag: &[u8], volume_uuid: &[u8; 16]) -> crate::Result<VolumeRecords> {
    /// RFC 3394 output for a 256-bit key.
    const WRAPPED_VEK_LEN: usize = 40;
    /// A `prange` is two little-endian u64s: block address then block count.
    const PRANGE_LEN: usize = 16;
    /// BER SEQUENCE wrapping a packed object.
    const TAG_SEQUENCE: u8 = 0x30;
    /// Context-specific constructed tag holding the wrapped-key object.
    const TAG_NESTED_OBJECT: u8 = 0xa3;
    /// BER tag carrying the wrapped key itself.
    const TAG_WRAPPED_KEY: u8 = 0x83;

    let bad = |field: &'static str, value: u64, cap: u64| crate::ApfsError::FieldOutOfRange {
        structure: "container_keybag",
        field,
        value,
        cap,
    };

    let nkeys = (crate::bytes::le_u16(keybag, KL_NKEYS) as usize).min(MAX_KEYBAG_ENTRIES);
    let mut wrapped_vek: Option<Vec<u8>> = None;
    let mut extent: Option<(u64, u64)> = None;

    let mut off = KL_ENTRIES_OFF;
    for _ in 0..nkeys {
        if off + KE_HEADER_LEN > keybag.len() {
            break;
        }
        let entry_uuid = keybag.get(off..off + 16).unwrap_or(&[]);
        let raw_tag = crate::bytes::le_u16(keybag, off + KE_TAG);
        let keylen = crate::bytes::le_u16(keybag, off + KE_KEYLEN) as usize;
        let data_off = off + KE_HEADER_LEN;
        let data = keybag.get(data_off..data_off + keylen).unwrap_or(&[]);

        if entry_uuid == volume_uuid.as_slice() {
            match KeybagTag::from_u16(raw_tag) {
                KeybagTag::VolumeKey => {
                    // Nested TWO levels, per the libfsapfs reference:
                    //   30 SEQUENCE { 80 version, 81 hmac(32), 82 meta(8),
                    //                 a3 { 83 wrapped key(40), 84 iters, 85 salt } }
                    // The 32-byte 0x81 is an HMAC, NOT key material. Reading it
                    // as the key is the mistake this comment exists to prevent.
                    let seq = ber_find(data, TAG_SEQUENCE).unwrap_or(data);
                    let obj = ber_find(seq, TAG_NESTED_OBJECT)
                        .ok_or_else(|| bad("volume_key_missing_0xa3", data.len() as u64, 0xa3))?;
                    let inner = ber_find(obj, TAG_WRAPPED_KEY)
                        .ok_or_else(|| bad("volume_key_missing_0x83", obj.len() as u64, 0x83))?;
                    if inner.len() != WRAPPED_VEK_LEN {
                        return Err(bad(
                            "wrapped_vek_len",
                            inner.len() as u64,
                            WRAPPED_VEK_LEN as u64,
                        ));
                    }
                    wrapped_vek = Some(inner.to_vec());
                }
                KeybagTag::VolumeUnlockRecords => {
                    if data.len() < PRANGE_LEN {
                        return Err(bad(
                            "unlock_records_len",
                            data.len() as u64,
                            PRANGE_LEN as u64,
                        ));
                    }
                    extent = Some((crate::bytes::le_u64(data, 0), crate::bytes::le_u64(data, 8)));
                }
                _ => {}
            }
        }
        off += ((KE_HEADER_LEN + keylen + 15) & !15).max(16);
    }

    let (blk, cnt) = extent.ok_or_else(|| bad("volume_unlock_records_absent", 0, 1))?;
    Ok(VolumeRecords {
        wrapped_vek: wrapped_vek.ok_or_else(|| bad("volume_key_absent", 0, 1))?,
        volume_keybag_block: blk,
        volume_keybag_blocks: cnt,
    })
}

/// A volume's unwrapped encryption key, recovered from a password.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UnlockedVolume {
    /// The volume encryption key: two AES-128-XTS keys, 32 bytes total.
    pub vek: Vec<u8>,
}

/// Unlock a volume: password -> KEK -> VEK.
///
/// 1. decrypt the container keybag (AES-128-XTS, container UUID as both keys)
/// 2. find this volume's wrapped VEK and where its own keybag lives
/// 3. decrypt the volume keybag (same scheme, VOLUME UUID as both keys)
/// 4. read the wrapped-KEK object: wrapped KEK, iterations, salt
/// 5. PBKDF2-HMAC-SHA256 the password with that salt and count
/// 6. AES-KW unwrap the KEK, then the VEK with it
///
/// Only step 5 uses the password. Everything before is keyed on UUIDs stored in
/// plaintext, which is why container structure reads while a volume stays locked.
///
/// # Errors
/// [`crate::ApfsError::FieldOutOfRange`] if a keybag is malformed, or if the
/// password is wrong — AES-KW's integrity check refuses it rather than handing
/// back a key that would decrypt to garbage.
pub fn unlock_volume(
    image: &[u8],
    volume_uuid: &[u8; 16],
    password: &str,
) -> crate::Result<UnlockedVolume> {
    let bad = |field: &'static str, value: u64, cap: u64| crate::ApfsError::FieldOutOfRange {
        structure: "unlock_volume",
        field,
        value,
        cap,
    };

    let container_kb = decrypt_container_keybag(image)?;
    let rec = volume_records(&container_kb, volume_uuid)?;

    let block_size = crate::bytes::le_u32(image, NX_BLOCK_SIZE) as usize;
    let start = (rec.volume_keybag_block as usize)
        .checked_mul(block_size)
        .ok_or_else(|| bad("vkb_offset", rec.volume_keybag_block, block_size as u64))?;
    let len = (rec.volume_keybag_blocks as usize)
        .checked_mul(block_size)
        .ok_or_else(|| bad("vkb_length", rec.volume_keybag_blocks, block_size as u64))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| bad("vkb_end", start as u64, len as u64))?;
    let ct = image
        .get(start..end)
        .ok_or_else(|| bad("vkb_past_image", end as u64, image.len() as u64))?;

    // The volume keybag uses the same scheme keyed on the VOLUME UUID.
    let volume_kb = xts_decrypt_area(ct, volume_uuid, start / KEYBAG_SECTOR);

    let obj = find_kek_object(&volume_kb)
        .ok_or_else(|| bad("kek_object_absent", volume_kb.len() as u64, 1))?;
    let kek_info = parse_wrapped_kek(obj)?;

    let derived_v =
        derive_key_from_password(password.as_bytes(), &kek_info.salt, kek_info.iterations, 32);
    let derived: [u8; 32] = derived_v
        .as_slice()
        .try_into()
        .map_err(|_| bad("derived_key_len", derived_v.len() as u64, 32))?;
    let wrapped_kek: [u8; 40] = kek_info
        .wrapped_key
        .as_slice()
        .try_into()
        .map_err(|_| bad("wrapped_kek_len", kek_info.wrapped_key.len() as u64, 40))?;

    let kek_v = aes_key_unwrap(&derived, &wrapped_kek)?;
    let kek: [u8; 32] = kek_v
        .as_slice()
        .try_into()
        .map_err(|_| bad("kek_len", kek_v.len() as u64, 32))?;
    let wrapped_vek: [u8; 40] = rec
        .wrapped_vek
        .as_slice()
        .try_into()
        .map_err(|_| bad("wrapped_vek_len", rec.wrapped_vek.len() as u64, 40))?;

    Ok(UnlockedVolume {
        vek: aes_key_unwrap(&kek, &wrapped_vek)?,
    })
}

/// Recover a volume key from an already-decrypted volume keybag.
///
/// The last link of the chain, taking only small buffers: the decrypted volume
/// keybag and the records naming this volume's wrapped key. A caller that can
/// seek reads two 4 KB areas, decrypts them with [`decrypt_keybag_area`], and
/// finishes here — never holding the image.
///
/// # Errors
/// When the keybag carries no KEK object, when a length is not what the format
/// fixes it at, or when AES key unwrap rejects the integrity check — which is
/// what a wrong password produces, and it is an error rather than wrong bytes.
pub fn unlock_with_volume_keybag(
    _volume_keybag: &[u8],
    _records: &VolumeRecords,
    _password: &str,
) -> crate::Result<UnlockedVolume> {
    Err(crate::ApfsError::FieldOutOfRange {
        structure: "unlock_with_volume_keybag",
        field: "unimplemented",
        value: 0,
        cap: 0,
    })
}

/// Decrypt a keybag area read from an arbitrary offset, without the image.
///
/// The rest of this module takes the whole image as one `&[u8]`, which is fine
/// for a 128 MB fixture and impossible for a 2 TB disk. The unwrap chain only
/// ever reads about 12 KB of an image — the superblock and two keybag blocks —
/// so the whole-image parameter expressed an assumption, not a requirement.
///
/// This is the entry point a caller uses when it can seek: hand it the
/// ciphertext it read, the UUID keying it (container UUID for the container
/// keybag, volume UUID for a volume keybag), and the absolute sector index the
/// area starts at. The sector index is not derivable from `ct` and is part of
/// the XTS tweak, so an offset error yields noise rather than a wrong-looking
/// success.
pub fn decrypt_keybag_area(ct: &[u8], uuid: &[u8; 16], first_sector: usize) -> Vec<u8> {
    xts_decrypt_area(ct, uuid, first_sector)
}

/// AES-128-XTS decrypt an area keyed by `uuid` (both XTS keys).
fn xts_decrypt_area(ct: &[u8], uuid: &[u8; 16], first_sector: usize) -> Vec<u8> {
    use aes::cipher::KeyInit;
    use xts_mode::{get_tweak_default, Xts128};
    let xts = Xts128::new(aes::Aes128::new(uuid.into()), aes::Aes128::new(uuid.into()));
    let mut buf = ct.to_vec();
    xts.decrypt_area(
        &mut buf,
        KEYBAG_SECTOR,
        first_sector as u128,
        get_tweak_default,
    );
    buf
}

/// Find the KEK object in a decrypted VOLUME keybag.
///
/// Tag semantics are CONTEXT-DEPENDENT and that is the trap: 0x03 means
/// "Keybag Ref" in the CONTAINER bag but "KEK" in the VOLUME bag. Matching only
/// `WrappingKey` (0x01) finds nothing in a real recs bag.
fn find_kek_object(keybag: &[u8]) -> Option<&[u8]> {
    let nkeys = (crate::bytes::le_u16(keybag, KL_NKEYS) as usize).min(MAX_KEYBAG_ENTRIES);
    let mut off = KL_ENTRIES_OFF;
    for _ in 0..nkeys {
        if off + KE_HEADER_LEN > keybag.len() {
            break;
        }
        let raw_tag = crate::bytes::le_u16(keybag, off + KE_TAG);
        let keylen = crate::bytes::le_u16(keybag, off + KE_KEYLEN) as usize;
        let data_off = off + KE_HEADER_LEN;
        let tag = KeybagTag::from_u16(raw_tag);
        if tag == KeybagTag::WrappingKey || tag == KeybagTag::VolumeUnlockRecords {
            if let Some(data) = keybag.get(data_off..data_off + keylen) {
                let seq = ber_find(data, 0x30).unwrap_or(data);
                if let Some(obj) = ber_find(seq, 0xa3) {
                    return Some(obj);
                }
            }
        }
        off += ((KE_HEADER_LEN + keylen + 15) & !15).max(16);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `kb_locker` keybag blob: 16-byte header (`kl_version`@0,
    /// `kl_nkeys`@2, `kl_nbytes`@4, pad), then `keybag_entry_t` entries
    /// (`ke_uuid`@0[16], `ke_tag`@16, `ke_keylen`@18, pad[4], `ke_keydata`@24),
    /// each 16-byte aligned (libfsapfs layout).
    fn keybag(entries: &[(u16, usize)]) -> Vec<u8> {
        // A real keybag block is an APFS object: a 32-byte obj_phys header
        // precedes the kb_locker, with the magic in o_type at +24. Building
        // without it produced a fixture that only this parser understood --
        // the test and the code shared one wrong assumption, so both passed.
        let mut data = vec![0u8; OBJ_PHYS_LEN + 16];
        data[24..28].copy_from_slice(b"keys"); // o_type
        data[OBJ_PHYS_LEN..OBJ_PHYS_LEN + 2].copy_from_slice(&1u16.to_le_bytes()); // kl_version
        data[OBJ_PHYS_LEN + 2..OBJ_PHYS_LEN + 4]
            .copy_from_slice(&(entries.len() as u16).to_le_bytes()); // kl_nkeys
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
        // Offset is derived, not hardcoded: entries begin after obj_phys +
        // kb_locker, so a header-size change moves this test with the format
        // instead of silently asserting a stale constant.
        assert_eq!(st.unknown_tags, vec![(0x55u16, KL_ENTRIES_OFF as u64)]);
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

    /// Tier-1: the production derivation must match RFC 7914 section 11's
    /// published PBKDF2-HMAC-SHA256 vector (c=80000) — third-party artifact and
    /// answer key, and a high iteration count so the loop is exercised rather
    /// than a single pass.
    ///
    /// Tests `derive_key_from_password` itself, not a test-only variant: a
    /// vector that validates a function production never calls proves nothing.
    #[test]
    fn pbkdf2_sha256_matches_rfc7914_vector() {
        let got = derive_key_from_password(b"Password", b"NaCl", 80_000, 64);
        let expected: [u8; 64] = [
            0x4D, 0xDC, 0xD8, 0xF6, 0x0B, 0x98, 0xBE, 0x21, 0x83, 0x0C, 0xEE, 0x5E, 0xF2, 0x27,
            0x01, 0xF9, 0x64, 0x1A, 0x44, 0x18, 0xD0, 0x4C, 0x04, 0x14, 0xAE, 0xFF, 0x08, 0x87,
            0x6B, 0x34, 0xAB, 0x56, 0xA1, 0xD4, 0x25, 0xA1, 0x22, 0x58, 0x33, 0x54, 0x9A, 0xDB,
            0x84, 0x1B, 0x51, 0xC9, 0xB3, 0x17, 0x6A, 0x27, 0x2B, 0xDE, 0xBB, 0xA1, 0xD0, 0x78,
            0x47, 0x8F, 0x62, 0xB3, 0x97, 0xF3, 0x3C, 0x8D,
        ];
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "RFC 7914 s11 PBKDF2-SHA256 c=80000"
        );
    }

    /// Load the committed fixture: a real macOS-minted APFS-native encrypted
    /// volume. Gzipped so CI validates from committed bytes with no download.
    #[cfg(test)]
    fn fixture_image() -> Vec<u8> {
        use std::io::Read as _;
        let gz = include_bytes!("../../tests/data/filevault/apfs-native-filevault.raw.gz");
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_end(&mut out)
            .expect("fixture must decompress");
        out
    }

    /// RED: the container keybag is stored AES-128-XTS encrypted, keyed by the
    /// container UUID (both XTS keys), tweaked by sector number. Decrypting it
    /// must yield a PARSEABLE keybag — not noise.
    ///
    /// Asserts on structure recovered from real Apple-written bytes, so a
    /// wrong key or tweak cannot pass: garbage does not parse into known tags.
    #[test]
    fn container_keybag_decrypts_to_a_parseable_keybag() {
        let img = fixture_image();
        let sb = &img[..4096];
        assert_eq!(
            &sb[32..36],
            b"NXSB",
            "fixture must start with a container superblock"
        );

        let kb = decrypt_container_keybag(&img).expect("container keybag must decrypt");
        let state = read_keybag(&kb).expect("decrypted keybag must parse");

        // A real container keybag names the per-volume key and unlock records.
        assert!(
            state.tags_present.contains(&KeybagTag::VolumeKey)
                || state.tags_present.contains(&KeybagTag::VolumeUnlockRecords),
            "decrypted container keybag must carry VolumeKey or VolumeUnlockRecords, got {:?}",
            state.tags_present
        );
    }

    /// RED: a wrong key must NOT yield something that parses as a keybag.
    /// Without this, "it parsed" could be an artifact of a permissive parser
    /// rather than evidence the decryption was correct.
    #[test]
    fn container_keybag_with_a_wrong_uuid_does_not_parse_as_a_keybag() {
        let img = fixture_image();
        let kb = decrypt_container_keybag_with_uuid(&img, &[0xAA; 16])
            .expect("decryption itself should run; only the RESULT must be wrong");
        let parsed = read_keybag(&kb);
        let bogus = match parsed {
            Err(_) => true,
            Ok(s) => {
                !s.tags_present.contains(&KeybagTag::VolumeKey)
                    && !s.tags_present.contains(&KeybagTag::VolumeUnlockRecords)
            }
        };
        assert!(
            bogus,
            "a wrong UUID must not produce a keybag carrying real volume tags"
        );
    }

    /// The volume UUID of the committed fixture, as reported independently by
    /// the libfsapfs oracle: 75aaf7f9-bf5a-4a4f-86c0-3ef90936bd7c.
    #[cfg(test)]
    const FIXTURE_VOLUME_UUID: [u8; 16] = [
        0x75, 0xAA, 0xF7, 0xF9, 0xBF, 0x5A, 0x4A, 0x4F, 0x86, 0xC0, 0x3E, 0xF9, 0x09, 0x36, 0xBD,
        0x7C,
    ];

    /// RED: the container keybag names, per volume, the wrapped VEK
    /// (`KB_TAG_VOLUME_KEY`) and where that volume's own keybag lives
    /// (`KB_TAG_VOLUME_UNLOCK_RECORDS`). Both are needed before a password can
    /// be applied.
    ///
    /// Asserts sizes and plausibility, not just presence: a 40-byte wrapped VEK
    /// is RFC 3394 output for a 256-bit key, and a keybag extent must land
    /// inside the image.
    #[test]
    fn container_keybag_yields_this_volumes_wrapped_vek_and_keybag_extent() {
        let img = fixture_image();
        let kb = decrypt_container_keybag(&img).expect("container keybag must decrypt");
        let rec = volume_records(&kb, &FIXTURE_VOLUME_UUID)
            .expect("the fixture's volume must be present in its container keybag");

        assert_eq!(
            rec.wrapped_vek.len(),
            40,
            "wrapped VEK must be RFC 3394 output for a 256-bit key"
        );
        assert!(
            rec.volume_keybag_block > 0,
            "volume keybag block must be set"
        );
        assert!(
            rec.volume_keybag_blocks > 0,
            "volume keybag length must be non-zero"
        );
        let end = (rec.volume_keybag_block as usize + rec.volume_keybag_blocks as usize) * 4096;
        assert!(
            end <= img.len(),
            "volume keybag extent must lie inside the container"
        );
    }

    /// RED: an unknown volume UUID must be REFUSED, not answered with the first
    /// volume that happens to be present. Returning the wrong volume's key
    /// material would decrypt to garbage and be misread as a corrupt volume.
    #[test]
    fn container_keybag_refuses_an_unknown_volume_uuid() {
        let img = fixture_image();
        let kb = decrypt_container_keybag(&img).expect("container keybag must decrypt");
        assert!(
            volume_records(&kb, &[0x11; 16]).is_err(),
            "an absent volume UUID must be an error, never another volume's keys"
        );
    }

    /// RED: the whole chain, end to end, on the real fixture with the real
    /// password — container keybag -> volume keybag -> KEK -> VEK.
    ///
    /// This is the test that decides whether volume unlock actually works.
    #[test]
    fn unlock_volume_recovers_the_vek_with_the_correct_password() {
        let img = fixture_image();
        let u = unlock_volume(&img, &FIXTURE_VOLUME_UUID, "apfs-FV-TEST-2026")
            .expect("the fixture must unlock with its recorded password");
        assert_eq!(u.vek.len(), 32, "VEK is two AES-128-XTS keys, 32 bytes");
        assert!(u.vek.iter().any(|&b| b != 0), "VEK must not be all zeros");
    }

    /// RED: a WRONG password must be refused by AES-KW's integrity check, never
    /// answered with bytes. Without this a wrong password yields a wrong key and
    /// every later failure is misattributed to a corrupt volume.
    #[test]
    fn unlock_volume_refuses_a_wrong_password() {
        let img = fixture_image();
        assert!(
            unlock_volume(&img, &FIXTURE_VOLUME_UUID, "not-the-password").is_err(),
            "a wrong password must fail the integrity check, never return a key"
        );
    }

    /// RED: the ranged entry point must recover EXACTLY what the whole-image
    /// path recovers.
    ///
    /// Why this matters beyond tidiness: every other entry point here demands
    /// the entire image as one slice. A 2 TB acquisition cannot be handed to
    /// one, so the code is untestable against real evidence — the defect a
    /// fixture-only suite structurally cannot see, because the fixture fits in
    /// RAM. Asserting byte equality against the path it replaces is what makes
    /// the ranged read trustworthy rather than merely convenient.
    #[test]
    fn keybag_area_decrypts_identically_from_a_ranged_read() {
        let img = fixture_image();

        // Exactly the fields a seeking caller reads out of the superblock.
        let block_size = crate::bytes::le_u32(&img, NX_BLOCK_SIZE) as usize;
        let paddr = crate::bytes::le_u64(&img, NX_KEYBAG_BLOCK) as usize;
        let blocks = crate::bytes::le_u64(&img, NX_KEYBAG_BLOCKS) as usize;
        let uuid: [u8; 16] = img[NX_CONTAINER_UUID..NX_CONTAINER_UUID + 16]
            .try_into()
            .expect("16 bytes");

        let start = paddr * block_size;
        let end = start + blocks * block_size;

        // Only the keybag blocks — what a ranged file read would return.
        let ranged = decrypt_keybag_area(&img[start..end], &uuid, start / KEYBAG_SECTOR);
        let whole = decrypt_container_keybag(&img).expect("whole-image path must decrypt");

        assert_eq!(
            ranged, whole,
            "a ranged read must decrypt to the same bytes as the whole-image path"
        );
        // `o_type` is a u32 CONSTANT, not a char array: the value spells "keys"
        // read big-endian, so on disk it lands byte-reversed as "syek". Taking
        // the module comment literally would assert b"keys" and never pass.
        assert_eq!(
            ranged.get(24..28),
            Some(&b"syek"[..]),
            "and those bytes must be a container keybag, not noise"
        );
    }

    /// Walk the whole unlock chain using ONLY ranged reads, and report how many
    /// bytes of the image were touched.
    ///
    /// This is the shape a caller with a 2 TB image must use, exercised here
    /// against the fixture so it is covered by the committed suite.
    #[cfg(test)]
    fn ranged_unlock(img: &[u8], volume_uuid: &[u8; 16], password: &str) -> (Vec<u8>, usize) {
        let mut bytes_read = 0usize;

        // (1) the superblock — the only fixed-offset read.
        let sb = &img[..4096];
        bytes_read += sb.len();
        let block_size = crate::bytes::le_u32(sb, NX_BLOCK_SIZE) as usize;
        let uuid: [u8; 16] = sb[NX_CONTAINER_UUID..NX_CONTAINER_UUID + 16]
            .try_into()
            .expect("16 bytes");
        let cs = crate::bytes::le_u64(sb, NX_KEYBAG_BLOCK) as usize * block_size;
        let ce = cs + crate::bytes::le_u64(sb, NX_KEYBAG_BLOCKS) as usize * block_size;

        // (2) the container keybag.
        bytes_read += ce - cs;
        let ckb = decrypt_keybag_area(&img[cs..ce], &uuid, cs / KEYBAG_SECTOR);
        let rec = volume_records(&ckb, volume_uuid).expect("volume must be listed");

        // (3) the volume keybag, keyed on the VOLUME uuid.
        let vs = rec.volume_keybag_block as usize * block_size;
        let ve = vs + rec.volume_keybag_blocks as usize * block_size;
        bytes_read += ve - vs;
        let vkb = decrypt_keybag_area(&img[vs..ve], volume_uuid, vs / KEYBAG_SECTOR);

        let vek = unlock_with_volume_keybag(&vkb, &rec, password)
            .map(|u| u.vek)
            .unwrap_or_default();
        (vek, bytes_read)
    }

    /// RED: the full chain must recover the SAME VEK from ranged reads as from
    /// the whole-image path, touching a trivial fraction of the image.
    ///
    /// The byte-count assertion is the one that matters for real evidence: it
    /// is the difference between an API that works on a 2 TB acquisition and
    /// one that only ever ran against a fixture small enough to hide the
    /// problem. Asserting VEK equality stops the cheap path from drifting into
    /// a different answer than the path it replaces.
    #[test]
    fn the_full_unlock_chain_works_from_ranged_reads_alone() {
        let img = fixture_image();
        let (got, bytes_read) = ranged_unlock(&img, &FIXTURE_VOLUME_UUID, "apfs-FV-TEST-2026");
        let want = unlock_volume(&img, &FIXTURE_VOLUME_UUID, "apfs-FV-TEST-2026")
            .expect("whole-image path must unlock");

        assert_eq!(
            got, want.vek,
            "the ranged chain must recover the same VEK as the whole-image path"
        );
        assert!(
            bytes_read <= 64 * 1024,
            "the unwrap chain must touch a trivial slice of the image, read {bytes_read} bytes"
        );
    }

    /// RED: a wrong password must be refused on the ranged path too. A cheaper
    /// route that quietly answers where the original refuses would be a
    /// security defect, not an optimisation.
    #[test]
    fn the_ranged_chain_refuses_a_wrong_password() {
        let img = fixture_image();
        let (vek, _) = ranged_unlock(&img, &FIXTURE_VOLUME_UUID, "not-the-password");
        assert!(
            vek.is_empty(),
            "a wrong password must fail the ranged chain, never return a key"
        );
    }

    /// RED: the absolute sector index is part of the XTS tweak and cannot be
    /// derived from the ciphertext. A caller that computes it wrongly must get
    /// noise, not a plausible-looking keybag — otherwise an offset bug reads as
    /// a decryption failure and gets misattributed to the password.
    #[test]
    fn keybag_area_with_a_wrong_sector_index_yields_noise() {
        let img = fixture_image();
        let block_size = crate::bytes::le_u32(&img, NX_BLOCK_SIZE) as usize;
        let paddr = crate::bytes::le_u64(&img, NX_KEYBAG_BLOCK) as usize;
        let blocks = crate::bytes::le_u64(&img, NX_KEYBAG_BLOCKS) as usize;
        let uuid: [u8; 16] = img[NX_CONTAINER_UUID..NX_CONTAINER_UUID + 16]
            .try_into()
            .expect("16 bytes");
        let start = paddr * block_size;
        let end = start + blocks * block_size;

        let wrong = decrypt_keybag_area(&img[start..end], &uuid, start / KEYBAG_SECTOR + 1);
        assert_eq!(
            wrong.len(),
            end - start,
            "a decrypted area must be the same length as its ciphertext"
        );
        assert_ne!(
            wrong.get(24..28),
            Some(&b"syek"[..]),
            "a wrong sector index must not still produce a valid keybag magic"
        );
    }
}
