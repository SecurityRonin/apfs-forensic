//! Drivers for the standalone analyzer wrappers that `audit_container` does not
//! reach on its own — they are invoked by callers holding the relevant inode /
//! encryption-state / integrity-metadata (see `audit_volume`'s doc comment).
//!
//! Each test exercises the real public `audit()` entry point over genuine inputs:
//! a real inode parsed from the committed macOS-authored `apfs_content.bin`, a
//! real snap-metadata tree walk over the same image, and encryption/integrity
//! states built from their public fields — never a synthetic anomaly asserted
//! against a synthetic seal (the Tier-3 trap the sealed-volume audit avoids).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::volume::ApfsVolume;
use apfs_forensic::AnomalyKind;

/// Build a `kb_locker` keybag blob: 16-byte header (`kl_version`@0, `kl_nkeys`@2,
/// `kl_nbytes`@4), then 16-byte-aligned `keybag_entry_t`s (`ke_tag`@16,
/// `ke_keylen`@18). Mirrors the builder in `core/src/encryption.rs` tests so the
/// forensic `crypto::audit` runs over a real `read_keybag`-parsed state.
fn keybag(entries: &[(u16, usize)]) -> Vec<u8> {
    let mut data = vec![0u8; 4096];
    data[0..2].copy_from_slice(&1u16.to_le_bytes());
    data[2..4].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    let mut off = 16usize;
    let mut nbytes = 16u32;
    for &(tag, keylen) in entries {
        let mut e = vec![0u8; (24 + keylen + 15) & !15];
        e[16..18].copy_from_slice(&tag.to_le_bytes());
        e[18..20].copy_from_slice(&(keylen as u16).to_le_bytes());
        data[off..off + e.len()].copy_from_slice(&e);
        off += e.len();
        nbytes += e.len() as u32;
    }
    data[4..8].copy_from_slice(&nbytes.to_le_bytes());
    data
}

/// The committed real macOS-authored APFS carve (repo-root `tests/data/`).
const CONTENT: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");
const BLOCK_SIZE: usize = 4096;
/// The live volume superblock (APSB) block in the P4 fixture (see
/// `core/tests/snapshot.rs`).
const APSB_BLOCK: usize = 438;

fn p4_volume() -> ApfsVolume {
    let block = &CONTENT[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
    ApfsVolume::parse(block).expect("parse live APSB")
}

fn codes(v: &[AnomalyKind]) -> Vec<&'static str> {
    v.iter().map(AnomalyKind::code).collect()
}

#[test]
fn timestamps_audit_on_a_real_inode_is_clean() {
    // plain.txt (inode 18) is a normally-created file: its four timestamps are
    // all set and consistently ordered, so the timestamp audit finds no leads.
    let mut r = Cursor::new(CONTENT);
    let vol = p4_volume();
    let inode = apfs_core::dir::load_inode(&mut r, &vol, 18, BLOCK_SIZE).expect("load inode 18");
    let findings = apfs_forensic::timestamps::audit(&inode);
    assert!(
        findings.is_empty(),
        "a normally-created file has no timestamp leads, got {:?}",
        codes(&findings)
    );
}

#[test]
fn crypto_audit_on_an_unencrypted_state_is_clean() {
    // An empty keybag → unencrypted, no unknown tags: a clean state surfaces no
    // findings (LOCKED/STATE are emitted only when key material is present).
    let state = apfs_core::encryption::read_keybag(&keybag(&[])).expect("parse empty keybag");
    assert!(!state.encrypted);
    let findings = apfs_forensic::crypto::audit(&state);
    assert!(
        findings.is_empty(),
        "an unencrypted clean keybag has no findings, got {:?}",
        codes(&findings)
    );
}

#[test]
fn crypto_audit_on_a_locked_state_with_unknown_tag_flags_both() {
    // A volume key (0x02 → encrypted) + a passphrase hint (0x04) + an
    // unrecognised tag (0x55): LOCKED (Info), STATE (Info), and a KEYBAG-ANOMALY
    // (Medium) carrying the raw tag + offset.
    let state = apfs_core::encryption::read_keybag(&keybag(&[(0x02, 32), (0x04, 8), (0x55, 4)]))
        .expect("parse keybag");
    assert!(state.encrypted);
    let codes = codes(&apfs_forensic::crypto::audit(&state));
    assert!(codes.contains(&"APFS-ENCRYPTION-LOCKED"));
    assert!(codes.contains(&"APFS-ENCRYPTION-STATE"));
    assert!(codes.contains(&"APFS-ENCRYPTION-KEYBAG-ANOMALY"));
}

#[test]
fn sealed_audit_on_an_unbroken_seal_is_clean() {
    // A zero `im_broken_xid` records an intact seal → no BROKEN finding. Build a
    // checksum-valid `integrity_meta_phys_t` (im_hash_type SHA-256, broken_xid 0)
    // — the same block layout `core/src/sealed.rs` parses — and drive the wrapper.
    let mut r = Cursor::new(CONTENT);
    let vol = p4_volume();
    let mut block = vec![0u8; BLOCK_SIZE];
    block[32..36].copy_from_slice(&1u32.to_le_bytes()); // im_version
    block[40..44].copy_from_slice(&1u32.to_le_bytes()); // im_hash_type = SHA-256
                                                        // im_broken_xid @48 left zero → intact seal.
    let cks = apfs_core::object::fletcher64_checksum(&block);
    block[0..8].copy_from_slice(&cks.to_le_bytes());
    let meta = apfs_core::sealed::IntegrityMeta::parse(&block).expect("parse integrity_meta");
    assert_eq!(meta.broken_xid, 0, "an intact seal records broken_xid == 0");
    let findings = apfs_forensic::sealed::audit(&mut r, &vol, &meta);
    assert!(
        findings.is_empty(),
        "an intact (broken_xid == 0) seal has no findings, got {:?}",
        codes(&findings)
    );
}

#[test]
fn sealed_audit_on_a_broken_seal_flags_it() {
    // A non-zero `im_broken_xid` records the seal was broken at that transaction →
    // one High APFS-SEALED-VOLUME-BROKEN observation carrying the raw xid.
    let mut r = Cursor::new(CONTENT);
    let vol = p4_volume();
    let mut block = vec![0u8; BLOCK_SIZE];
    block[32..36].copy_from_slice(&1u32.to_le_bytes());
    block[40..44].copy_from_slice(&1u32.to_le_bytes());
    block[48..56].copy_from_slice(&4242u64.to_le_bytes()); // im_broken_xid
    let cks = apfs_core::object::fletcher64_checksum(&block);
    block[0..8].copy_from_slice(&cks.to_le_bytes());
    let meta = apfs_core::sealed::IntegrityMeta::parse(&block).expect("parse integrity_meta");
    let findings = apfs_forensic::sealed::audit(&mut r, &vol, &meta);
    assert_eq!(codes(&findings), vec!["APFS-SEALED-VOLUME-BROKEN"]);
}

#[test]
fn snapshots_audit_on_the_unsnapshotted_fixture_is_clean() {
    // The P4 fixture has zero snapshots: the snapshot audit walks the (empty)
    // snap-metadata tree and returns no findings — never a bootstrap error.
    let mut r = Cursor::new(CONTENT);
    let vol = p4_volume();
    let findings =
        apfs_forensic::snapshots::audit(&mut r, &vol, BLOCK_SIZE).expect("snapshot audit");
    assert!(
        findings.is_empty(),
        "an unsnapshotted volume has no snapshot findings, got {:?}",
        codes(&findings)
    );
}
