//! Verify an APFS volume password against a raw image, revealing nothing.
//!
//! Reads the password from STDIN ONLY. Never from argv (visible to any user on
//! the box via `ps`) and never from an environment variable (readable out of
//! /proc on Linux). Prints one verdict plus a short fingerprint of the
//! recovered key — never the key, never the password, never anything derived
//! from either that could be reversed.
//!
//! Opens the image READ-ONLY, seeks, and reads about 12 KB: one superblock and
//! two keybag areas. It never loads the image, so a 2 TB acquisition costs the
//! same as a 128 MB fixture.
//!
//!     read -s -p "Password: " PW && printf '%s' "$PW" | \
//!       cargo run -q --example unlock_check -- /path/to/image.raw ; unset PW

use apfs_core::encryption::{decrypt_keybag_area, unlock_with_volume_keybag, volume_records};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};

// Container superblock (nx_superblock_t) field offsets.
const NX_BLOCK_SIZE: u64 = 0x024;
const NX_CONTAINER_UUID: usize = 0x048;
const NX_KEYBAG_BLOCK: u64 = 0x510;
const NX_KEYBAG_BLOCKS: u64 = 0x518;
const KEYBAG_SECTOR: usize = 512;

/// A keybag area far larger than any real one is a corrupt length, not a keybag.
const MAX_KEYBAG_BYTES: u64 = 1 << 20;

fn main() -> std::process::ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: unlock_check <image>   (password on stdin)");
        return std::process::ExitCode::from(2);
    };

    let mut password = String::new();
    if std::io::stdin().read_to_string(&mut password).is_err() {
        eprintln!("could not read the password from stdin");
        return std::process::ExitCode::from(2);
    }
    // A trailing newline from `read` or a here-string is not the password.
    let password = password.trim_end_matches(['\n', '\r']);

    match run(&path, password) {
        Ok(o) => {
            if let Some((uuid, fp, len)) = o.unlocked {
                println!("UNLOCKED");
                println!("  volume          : {}", uuid_str(&uuid));
                println!("  key length      : {len} bytes");
                println!("  key fingerprint : {}  (sha256, first 8 bytes)", hex(&fp));
                println!("  image bytes read: {}", o.bytes_read);
                return std::process::ExitCode::SUCCESS;
            }
            // On a damaged image these two are different findings, and only
            // one of them is about the password. Reporting them the same way
            // would send someone hunting for a passphrase that was never the
            // problem.
            if o.volumes_tried == 0 {
                println!("NO VOLUME KEYBAG READABLE");
                println!(
                    "  volumes named by the container keybag : {}",
                    o.volumes_found
                );
                println!("  volumes whose own keybag decrypted    : 0");
                println!("  the password was never tested: there was nothing to test it");
                println!("  against. This is an image-completeness result, not a password one.");
                println!("  image bytes read: {}", o.bytes_read);
                return std::process::ExitCode::from(3);
            }
            println!("REFUSED");
            println!(
                "  volumes named by the container keybag : {}",
                o.volumes_found
            );
            println!(
                "  volumes the password was tried against: {}",
                o.volumes_tried
            );
            println!("  every one refused it at the AES-KW integrity check, so the");
            println!("  structures are intact and the password did not match.");
            println!("  image bytes read: {}", o.bytes_read);
            std::process::ExitCode::from(1)
        }
        Err(e) => {
            // The CLASS of failure only. An io::Error's message carries the
            // path, and a path is not this tool's to print.
            eprintln!("could not read the image structures: {e}");
            std::process::ExitCode::from(2)
        }
    }
}

/// What the tool established, separated from whether the password worked.
struct Outcome {
    /// Volumes named by the container keybag.
    volumes_found: usize,
    /// Volumes whose own keybag was readable and decrypted -- the ones the
    /// password actually got tried against.
    volumes_tried: usize,
    bytes_read: u64,
    /// `Some` only when a volume key was recovered.
    unlocked: Option<([u8; 16], [u8; 8], usize)>,
}

fn run(path: &str, password: &str) -> std::io::Result<Outcome> {
    let mut f = File::open(path)?;
    let mut read_total = 0u64;

    // (1) The container superblock — the only fixed-offset read.
    let sb = read_at(&mut f, 0, 4096, &mut read_total)?;
    if sb.get(32..36) != Some(b"NXSB") {
        return Err(err("no NXSB container superblock at offset 0"));
    }
    let block_size = u64::from(le_u32(&sb, NX_BLOCK_SIZE as usize));
    if block_size == 0 || block_size > MAX_KEYBAG_BYTES {
        return Err(err("container block size is not a usable value"));
    }
    let container_uuid: [u8; 16] = sb[NX_CONTAINER_UUID..NX_CONTAINER_UUID + 16]
        .try_into()
        .map_err(|_| err("short superblock"))?;

    // (2) The container keybag, keyed on the CONTAINER uuid.
    let kb_start = le_u64(&sb, NX_KEYBAG_BLOCK as usize)
        .checked_mul(block_size)
        .ok_or_else(|| err("keybag offset overflows"))?;
    let kb_len = le_u64(&sb, NX_KEYBAG_BLOCKS as usize)
        .checked_mul(block_size)
        .ok_or_else(|| err("keybag length overflows"))?;
    if kb_start == 0 || kb_len == 0 {
        return Err(err(
            "this container declares no keybag: it is not encrypted",
        ));
    }
    if kb_len > MAX_KEYBAG_BYTES {
        return Err(err("declared keybag length is implausible"));
    }
    let ct = read_at(&mut f, kb_start, kb_len as usize, &mut read_total)?;
    let container_kb = decrypt_keybag_area(
        &ct,
        &container_uuid,
        (kb_start / KEYBAG_SECTOR as u64) as usize,
    );
    if container_kb.get(24..28) != Some(b"syek") {
        // o_type is a u32 constant; the value spelling "keys" big-endian lands
        // on disk as "syek". Its absence means the area did not decrypt.
        return Err(err(
            "the container keybag did not decrypt — the area is damaged, or this is not \
             an APFS-native encrypted container",
        ));
    }

    // (3) Each volume named by the keybag, until one unlocks.
    let uuids = keybag_uuids(&container_kb);
    let mut volumes_found = 0usize;
    let mut volumes_tried = 0usize;
    for uuid in uuids {
        let Ok(rec) = volume_records(&container_kb, &uuid) else {
            continue;
        };
        volumes_found += 1;
        let vs = rec.volume_keybag_block.saturating_mul(block_size);
        let vlen = rec.volume_keybag_blocks.saturating_mul(block_size);
        if vs == 0 || vlen == 0 || vlen > MAX_KEYBAG_BYTES {
            continue;
        }
        let Ok(vct) = read_at(&mut f, vs, vlen as usize, &mut read_total) else {
            // A partially recovered image can simply not contain this area.
            continue;
        };
        let vkb = decrypt_keybag_area(&vct, &uuid, (vs / KEYBAG_SECTOR as u64) as usize);
        // "recs" stored as a u32 constant, byte-reversed on disk like "syek".
        if vkb.get(24..28) != Some(b"scer") {
            continue;
        }
        volumes_tried += 1;

        if let Ok(u) = unlock_with_volume_keybag(&vkb, &rec, password) {
            let mut fp = [0u8; 8];
            fp.copy_from_slice(&sha256(&u.vek)[..8]);
            return Ok(Outcome {
                volumes_found,
                volumes_tried,
                bytes_read: read_total,
                unlocked: Some((uuid, fp, u.vek.len())),
            });
        }
    }
    Ok(Outcome {
        volumes_found,
        volumes_tried,
        bytes_read: read_total,
        unlocked: None,
    })
}

/// UUIDs of the entries in a decrypted keybag.
fn keybag_uuids(kb: &[u8]) -> Vec<[u8; 16]> {
    const ENTRIES_OFF: usize = 32 + 16; // obj_phys + kb_locker
    const HEADER: usize = 24; // uuid(16) + tag(2) + keylen(2) + pad(4)
    let nkeys = usize::from(le_u16(kb, 32 + 2)).min(4096);
    let mut out: Vec<[u8; 16]> = Vec::new();
    let mut off = ENTRIES_OFF;
    for _ in 0..nkeys {
        if off + HEADER > kb.len() {
            break;
        }
        if let Ok(u) = <[u8; 16]>::try_from(&kb[off..off + 16]) {
            if u.iter().any(|&b| b != 0) && !out.contains(&u) {
                out.push(u);
            }
        }
        let keylen = usize::from(le_u16(kb, off + 18));
        off += ((HEADER + keylen + 15) & !15).max(16);
    }
    out
}

fn read_at(f: &mut File, off: u64, len: usize, total: &mut u64) -> std::io::Result<Vec<u8>> {
    f.seek(SeekFrom::Start(off))?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    *total += len as u64;
    Ok(buf)
}

fn err(m: &str) -> std::io::Error {
    std::io::Error::other(m.to_string())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(data).into()
}

fn le_u16(d: &[u8], o: usize) -> u16 {
    d.get(o..o + 2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map_or(0, u16::from_le_bytes)
}

fn le_u32(d: &[u8], o: usize) -> u32 {
    d.get(o..o + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or(0, u32::from_le_bytes)
}

fn le_u64(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 8)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map_or(0, u64::from_le_bytes)
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn uuid_str(u: &[u8; 16]) -> String {
    let h = hex(u);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}
