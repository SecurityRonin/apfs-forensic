//! Directory records (`APFS_TYPE_DIR_REC 9`) and name→inode navigation.
//!
//! A directory entry's key is `j_drec_key_t` (parent oid + name) or, on
//! case-insensitive/normalization-aware volumes, `j_drec_hashed_key_t` (parent
//! oid + a packed name-length/hash word + name). After the 8-byte `j_key`
//! header:
//!
//! - **unhashed** (`j_drec_key_t`): `name_len` u16 @8 (incl. the NUL), name @10.
//! - **hashed** (`j_drec_hashed_key_t`): `name_len_and_hash` u32 @8
//!   (`J_DREC_LEN_MASK 0x000003ff` = name length incl. NUL,
//!   `J_DREC_HASH_SHIFT 10` for the 22-bit hash), name @12.
//!
//! The value `j_drec_val_t { u64 file_id; u64 date_added; u16 flags; xfields }`
//! gives the target inode (`file_id`) and the time the entry was added
//! (`date_added`). Layout verified verbatim against the Apple reference +
//! libfsapfs format spec.
//!
//! **Navigation** resolves a path component by scanning the volume fs-tree for
//! the `DIR_REC` whose key oid is the parent inode and whose name matches the
//! requested component, returning the child inode (`file_id`); full-path
//! resolution descends from `ROOT_DIR_INO_NUM` (2). The fs-tree is *virtual* —
//! its node oids resolve through the volume object map at the volume's xid.

use std::io::{Read, Seek};

use crate::btree::{self, BTreeSubtype};
use crate::fsrecord::{decode_jkey, RecordType};
use crate::inode::Inode;
use crate::object::{fletcher64_checksum, fletcher64_stored, ObjPhys};
use crate::omap::ObjectMap;
use crate::volume::ApfsVolume;

/// `ROOT_DIR_INO_NUM` (Apple) — the inode number of a volume's root directory.
pub const ROOT_DIR_INO_NUM: u64 = 2;

/// `j_drec_hashed_key_t` name-length mask (low 10 bits of `name_len_and_hash`).
const J_DREC_LEN_MASK: u32 = 0x0000_03ff;

// j_drec_val_t value field offsets.
const OFF_DREC_FILE_ID: usize = 0;
const OFF_DREC_DATE_ADDED: usize = 8;
const OFF_DREC_FLAGS: usize = 16;

/// Depth cap on a path descent / fs-tree walk (cyclic-oid guard).
const MAX_FSTREE_DEPTH: usize = 64;

/// A directory entry.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DirEntry {
    /// The entry name (the directory-record key's name string).
    pub name: String,
    /// `file_id` — the target inode number.
    pub file_id: u64,
    /// `date_added` — when the entry was added (ns since 1970, distinct from the
    /// inode's own timestamps; not updated on an in-place rename).
    pub date_added: u64,
    /// Directory-entry flags (`j_drec_val_t.flags`).
    pub flags: u16,
}

/// Decode a `DIR_REC` key's name. The key begins with the 8-byte `j_key` header;
/// the name layout depends on whether the volume uses hashed keys. The hashed
/// form is detected structurally: its 4-byte `name_len_and_hash` low-10-bit
/// length plus a name at offset 12 must fit the key; otherwise the unhashed
/// (u16 length @8, name @10) form is used. Returns `None` if neither form's
/// length fits the key slice (never panics, never over-reads).
fn decode_drec_name(key: &[u8]) -> Option<String> {
    // Hashed key: name_len_and_hash u32 @8, name @12.
    let hashed_len = (crate::bytes::le_u32(key, 8) & J_DREC_LEN_MASK) as usize;
    if hashed_len > 0 {
        if let Some(name) = key.get(12..12 + hashed_len) {
            return Some(decode_cstr(name));
        }
    }
    // Unhashed key: name_len u16 @8, name @10.
    let unhashed_len = crate::bytes::le_u16(key, 8) as usize;
    if unhashed_len > 0 {
        if let Some(name) = key.get(10..10 + unhashed_len) {
            return Some(decode_cstr(name));
        }
    }
    None
}

/// Parse a `DIR_REC` (key, value) pair into a [`DirEntry`]. `None` if the name
/// cannot be decoded from the key (a malformed record is skipped, not fatal).
fn parse_dir_entry(key: &[u8], value: &[u8]) -> Option<DirEntry> {
    let name = decode_drec_name(key)?;
    Some(DirEntry {
        name,
        file_id: crate::bytes::le_u64(value, OFF_DREC_FILE_ID),
        date_added: crate::bytes::le_u64(value, OFF_DREC_DATE_ADDED),
        flags: crate::bytes::le_u16(value, OFF_DREC_FLAGS),
    })
}

/// Walk the volume fs-tree (a *virtual* B-tree resolved through the volume omap),
/// invoking `visit(key, value)` for every leaf record. Each node's virtual oid is
/// resolved to a physical block via the omap at the volume's xid, the node's
/// Fletcher-64 checksum is verified before its TOC is trusted, the descent depth
/// is capped, and a visited-set guards against cyclic node oids.
fn for_each_fs_record<R, F>(
    reader: &mut R,
    volume: &ApfsVolume,
    block_size: usize,
    visit: &mut F,
) -> crate::Result<()>
where
    R: Read + Seek,
    F: FnMut(&[u8], &[u8]),
{
    // Read the volume omap header (a physical object at apfs_omap_oid).
    let mut buf = vec![0u8; block_size];
    let omap_off = volume.omap_oid().saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(omap_off))?;
    reader.read_exact(&mut buf)?;
    let omap = ObjectMap::parse(&buf)?;

    let xid = volume.xid();
    let mut visited = std::collections::HashSet::new();
    descend_virtual(
        reader,
        &omap,
        volume.root_tree_oid(),
        xid,
        block_size,
        0,
        &mut visited,
        visit,
    )
}

#[allow(clippy::too_many_arguments)]
fn descend_virtual<R, F>(
    reader: &mut R,
    omap: &ObjectMap,
    node_oid: u64,
    xid: u64,
    block_size: usize,
    depth: usize,
    visited: &mut std::collections::HashSet<u64>,
    visit: &mut F,
) -> crate::Result<()>
where
    R: Read + Seek,
    F: FnMut(&[u8], &[u8]),
{
    if depth >= MAX_FSTREE_DEPTH {
        return Err(crate::ApfsError::CycleGuard {
            cap: MAX_FSTREE_DEPTH,
        });
    }
    if !visited.insert(node_oid) {
        return Err(crate::ApfsError::CycleGuard {
            cap: MAX_FSTREE_DEPTH,
        });
    }

    // Resolve this node's virtual oid to a physical block via the omap.
    let entry = omap.resolve(reader, node_oid, xid, block_size)?;

    let mut buf = vec![0u8; block_size];
    let offset = entry.paddr.saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(offset))?;
    reader.read_exact(&mut buf)?;

    // Checksum-before-trust.
    let stored = fletcher64_stored(&buf);
    let computed = fletcher64_checksum(&buf);
    if stored != computed {
        let block = ObjPhys::parse(&buf).map_or(entry.paddr, |h| h.oid);
        return Err(crate::ApfsError::ChecksumMismatch {
            block,
            stored,
            computed,
        });
    }

    let Some(hdr) = btree::parse_node_header(&buf) else {
        return Ok(()); // cov:unreachable: buf is block_size >= node header length
    };

    if hdr.is_leaf() {
        for e in btree::node_entries(&buf, BTreeSubtype::FsTree) {
            visit(e.key, e.value);
        }
        return Ok(());
    }

    // Index node: each value is an 8-byte child *virtual* oid; descend each.
    let children: Vec<u64> = btree::node_entries(&buf, BTreeSubtype::FsTree)
        .iter()
        .map(|e| crate::bytes::le_u64(e.value, 0))
        .collect();
    for child in children {
        descend_virtual(
            reader,
            omap,
            child,
            xid,
            block_size,
            depth + 1,
            visited,
            visit,
        )?;
    }
    Ok(())
}

/// List the directory entries whose parent is `parent_oid`, scanning the volume
/// fs-tree for `DIR_REC` records.
///
/// # Errors
/// [`crate::ApfsError::OmapUnresolved`] / [`crate::ApfsError::ChecksumMismatch`]
/// / [`crate::ApfsError::CycleGuard`] / [`crate::ApfsError::Io`] on a
/// structurally invalid omap/fs-tree or a read failure.
pub fn list_dir<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    parent_oid: u64,
    block_size: usize,
) -> crate::Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    for_each_fs_record(reader, volume, block_size, &mut |key, value| {
        let (oid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty != Some(RecordType::DirRec) || oid != parent_oid {
            return;
        }
        if let Some(entry) = parse_dir_entry(key, value) {
            out.push(entry);
        }
    })?;
    Ok(out)
}

/// Resolve a single path component: look up the `DIR_REC` `(parent_oid, name)` in
/// the fs-tree and return the child inode number, or `None` if absent.
///
/// # Errors
/// As [`list_dir`].
pub fn lookup_child<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    parent_oid: u64,
    name: &str,
    block_size: usize,
) -> crate::Result<Option<u64>> {
    let mut found = None;
    for_each_fs_record(reader, volume, block_size, &mut |key, value| {
        if found.is_some() {
            return;
        }
        let (oid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty != Some(RecordType::DirRec) || oid != parent_oid {
            return;
        }
        if let Some(entry) = parse_dir_entry(key, value) {
            if entry.name == name {
                found = Some(entry.file_id);
            }
        }
    })?;
    Ok(found)
}

/// Load the inode (`INODE` record) for `oid` from the volume fs-tree.
///
/// # Errors
/// [`crate::ApfsError::OmapUnresolved`] if the inode record is not present (a
/// loud per-item miss), plus the structural errors of [`list_dir`].
pub fn load_inode<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    oid: u64,
    block_size: usize,
) -> crate::Result<Inode> {
    let mut value: Option<Vec<u8>> = None;
    for_each_fs_record(reader, volume, block_size, &mut |key, val| {
        if value.is_some() {
            return;
        }
        let (k_oid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty == Some(RecordType::Inode) && k_oid == oid {
            value = Some(val.to_vec());
        }
    })?;
    let value = value.ok_or(crate::ApfsError::OmapUnresolved {
        oid,
        xid: volume.xid(),
    })?;
    Inode::parse(oid, &value)
}

/// Resolve a `/`-separated path to an [`Inode`] by descending the fs-tree from
/// the root directory (`ROOT_DIR_INO_NUM`). Empty components (from a leading,
/// trailing, or doubled `/`) are skipped; `"/"` resolves to the root inode.
///
/// # Errors
/// [`crate::ApfsError::OmapUnresolved`] if any path component is not found or the
/// final inode record is absent (a loud per-item miss), plus the structural
/// errors of [`list_dir`].
pub fn open_path<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    path: &str,
    block_size: usize,
) -> crate::Result<Inode> {
    let mut current = ROOT_DIR_INO_NUM;
    for component in path.split('/').filter(|c| !c.is_empty()) {
        match lookup_child(reader, volume, current, component, block_size)? {
            Some(child) => current = child,
            None => {
                return Err(crate::ApfsError::OmapUnresolved {
                    oid: current,
                    xid: volume.xid(),
                });
            }
        }
    }
    load_inode(reader, volume, current, block_size)
}

/// Decode a NUL-terminated UTF-8 byte string. Bytes after the first NUL are
/// dropped; invalid UTF-8 is replaced (never panics).
fn decode_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}
