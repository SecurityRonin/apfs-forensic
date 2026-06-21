# apfs-forensic — Design & Research Document

**Status:** Design + research only (no parser implementation). Drives a multi-week build.
**Author:** Albert Hui · **Date:** 2026-06-21 · **Repo:** `~/src/apfs-forensic` (local, unpushed)
**Reference impl this mirrors:** `ntfs-forensic` (Pattern A: `core/` reader + `forensic/` analyzer)

> All on-disk struct claims in this document are cited to **Apple's *Apple File System
> Reference*, edition 2020-06-22** (the primary on-disk spec) and cross-checked against
> **libfsapfs**'s reverse-engineered format spec. Constants were extracted verbatim from
> those two sources, not from memory. Anything not directly confirmed is marked **[UNVERIFIED]**.

---

## Executive Summary

**Decision: build `apfs-core` + `apfs-forensic` from scratch.** No mature Rust APFS reader exists
on crates.io — the closest (`apfs` 0.2.4, 771 downloads, read-only, tied to a DMG-extraction tool;
`exhume_apfs` 0.1.6, 292 downloads, early-stage, no public repo) are neither forensic-grade nor
maintained as libraries. They serve as **cross-check oracles**, not dependencies. The authoritative
references are excellent: Apple's own *APFS Reference* PDF (the on-disk spec) plus libfsapfs's
121 KB reverse-engineered format spec. The fleet already owns the transparent-compression codec
stack (`forensicnomicon::decmpfs` + `lzfse_rust` + our `lzvn` + `flate2`, validated against macOS in
`hfsplus-forensic`), which APFS reuses verbatim, so file-read decompression is a solved problem we
inherit.

The crate pair sits in the **FILESYSTEM layer** of the fleet: it consumes a CONTAINER sector stream
(`Read + Seek`) and navigates by path (name → inode → file-extents → bytes), the APFS analogue of
NTFS's name → inode → data-runs. The analyzer's forensic differentiator is APFS-specific: **snapshot
and checkpoint-ring tampering, sealed/signed-system-volume integrity violations, object-map
inconsistencies, recoverable deleted file-system records** (APFS is copy-on-write — superseded
objects survive in older checkpoints and unreaped space until overwritten), **clone/dedup analysis,
and encryption-state surfacing**.

Validation is well-supplied on the development host: macOS itself (mount APFS read-only and diff),
**The Sleuth Kit** `fsstat`/`fls`/`istat` (installed, v4.12.1, has APFS support), plus mintable
corpora via `hdiutil create -fs APFS` + `diskutil apfs` + `tmutil` for snapshots. `fsapfsinfo`
(libfsapfs) and `apfsck` (apfsprogs) are **not yet installed** and must be built to serve as the
structural oracles.

---

## 1. Research Summary

### 1.1 Prior-art / source table

| Source | What it provides | License | Reuse vs Oracle | URL |
|---|---|---|---|---|
| **Apple, *APFS Reference*** (2020-06-22) | THE primary on-disk spec: every struct (`nx_superblock_t`, `omap_phys_t`, `btree_node_phys_t`, `apfs_superblock_t`, `j_*` records), magics, object types, checksum algorithm, checkpoint algorithm, keybag, sealed volume, Fusion | Apple docs (read for spec; we author original Rust) | **Spec — primary** | https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf |
| **libfsapfs** (Joachim Metz / libyal) | Most thorough C reference impl + 121 KB format spec; field offsets/sizes, keybag tag values, B-tree entry layouts; `fsapfsinfo` CLI | **LGPL-3.0** | **ORACLE only** (`fsapfsinfo`); cannot link into `forbid(unsafe)` pure-Rust crate; spec is study-reference | https://github.com/libyal/libfsapfs |
| **apfs-fuse** (sgan81) | C++ FUSE driver; handles decmpfs (LZFSE/LZVN/zlib) + encryption (keybag unwrap) | **GPL-2.0** | **ORACLE / study** (mount-and-diff); no code reuse | https://github.com/sgan81/apfs-fuse |
| **apfsprogs / linux-apfs-rw** (E. A. Fernández) | Linux kmod + tools incl. **`apfsck`** (structural fsck — excellent integrity oracle) | GPL-2.0 (no SPDX tag detected; GPL per source headers) | **ORACLE** (`apfsck` structural check); no reuse | https://github.com/eafer/apfsprogs |
| **dissect.apfs** (Fox-IT) | Clean Python RE reference, well-structured | **AGPL-3.0** *(task said MIT — corrected)* | **Study reference only**; AGPL means we do NOT copy code or structure verbatim — read for understanding, author original | https://github.com/fox-it/dissect.apfs |
| **The Sleuth Kit** (APFS support, BlackBag/Cellebrite contribution) | `fls`/`istat`/`fsstat`/`mmls` on APFS — installed (v4.12.1) | CPL/IPL/GPL (tool, not linked) | **ORACLE — primary, already installed** | https://github.com/sleuthkit/sleuthkit |
| **cugu/apfs.ksy** (Kaitai Struct) | Machine-readable struct definitions; the DFRWS-paper author's format model | **MIT** | **Cross-check / study** (MIT = freely usable as reference) | https://github.com/cugu/apfs.ksy |
| **Hansen & Toolan, "Decoding the APFS file system"** (DFRWS EU 2017, *Digital Investigation* 22:S107–S132) | Seminal pre-Apple-reference RE; the forensic foundation | Paper (cite) | **Background / citation** | doi:10.1016/j.diin.2017.06.010 |
| **`apfs` crate** (Dil4rd) | Read-only APFS parser, 0.2.4, 771 dl, part of `dpp` DMG tool | (crate) | **Cross-check oracle**; not mature/forensic → justifies building ours | https://crates.io/crates/apfs |
| **`exhume_apfs` crate** | Early "proposing APFS parsing", 0.1.6, 292 dl, no public repo | (crate) | Note as prior attempt; not a dependency | https://crates.io/crates/exhume_apfs |
| **mac_apt** (Yogesh Khatri) | macOS artifact-parsing framework with APFS handling; significant DFIR prior art for APFS-backed artifacts | MIT/ASL | **Study / artifact-level oracle** (not a low-level on-disk reader) | https://github.com/ydkhatri/mac_apt |
| **pyfsapfs / dfVFS** | libfsapfs Python bindings used by dfVFS/Plaso; an ecosystem oracle path | Apache-2.0 (dfVFS) / LGPL (pyfsapfs) | **Oracle** (scriptable libfsapfs) | https://github.com/libyal/libfsapfs / https://github.com/log2timeline/dfvfs |

**Build-vs-reuse verdict:** No mature Rust APFS library exists. The two crates that parse APFS are
read-only, low-adoption, and embedded in unrelated DMG tooling. Per the fleet "prefer our own /
reuse mature" rule, the absence of a maintained, forensic-grade reader **justifies building**
`apfs-core`. The existing crates + `fsapfsinfo` + TSK + `apfsck` + macOS-mount become the
independent validation oracles (Doer-Checker). The one piece we **do** reuse is the decmpfs codec
stack the fleet already owns.

### 1.2 Authoritative constants (extracted verbatim from Apple Reference + libfsapfs)

**Magics** (Apple `#define`s; note Apple writes them as four-char codes; the on-disk little-endian
u32 is what we compare):

| Constant | Apple 4CC | Hex dump string | On-disk LE u32 |
|---|---|---|---|
| `NX_MAGIC` | `'BSXN'` | "NXSB" | `0x4253584E` |
| `APFS_MAGIC` | `'BSPA'` | "APSB" | `0x42535041` |
| `NX_EFI_JUMPSTART_MAGIC` | `'RDSJ'` | "JSDR" | `0x5244534A` |
| `ER_MAGIC` (encryption-rolling state) | `'FLAB'` | "BALF" | `0x464C4142` |

These match the task's stated NXSB `0x4253584E` and APSB `0x42535041`. ✓

**Block sizes** (Apple): `NX_MINIMUM_BLOCK_SIZE 4096`, `NX_DEFAULT_BLOCK_SIZE 4096`,
`NX_MAXIMUM_BLOCK_SIZE 65536`, `NX_MINIMUM_CONTAINER_SIZE 1048576`. Actual block size is read from
`nx_block_size`, never assumed.

**Object header** `obj_phys_t` (32 bytes; `MAX_CKSUM_SIZE 8`):
`o_cksum[8]` + `o_oid (u64)` + `o_xid (u64)` + `o_type (u32)` + `o_subtype (u32)`.

**Object types** `o_type & OBJECT_TYPE_MASK (0x0000ffff)` — storage flags in `OBJ_STORAGETYPE_MASK
(0xc0000000)`; `OBJECT_TYPE_FLAGS_MASK 0xffff0000`. **Complete list, verbatim from Apple** (all
confirmed against the reference, corrected after Codex flagged the original list as truncated):
`INVALID 0x0`, `NX_SUPERBLOCK 0x1`, `BTREE 0x2`, `BTREE_NODE 0x3`, `SPACEMAN 0x5`,
`SPACEMAN_CAB 0x6`, `SPACEMAN_CIB 0x7`, `SPACEMAN_BITMAP 0x8`, `SPACEMAN_FREE_QUEUE 0x9`,
`EXTENT_LIST_TREE 0xa`, `OMAP 0xb`, `CHECKPOINT_MAP 0xc`, `FS 0xd`, `FSTREE 0xe`,
`BLOCKREFTREE 0xf`, `SNAPMETATREE 0x10`, `NX_REAPER 0x11`, `NX_REAP_LIST 0x12`,
`OMAP_SNAPSHOT 0x13`, `EFI_JUMPSTART 0x14`, `FUSION_MIDDLE_TREE 0x15`, `NX_FUSION_WBC 0x16`,
`NX_FUSION_WBC_LIST 0x17`, `ER_STATE 0x18`, `GBITMAP 0x19`, `GBITMAP_TREE 0x1a`,
`GBITMAP_BLOCK 0x1b`, `ER_RECOVERY_BLOCK 0x1c`, `SNAP_META_EXT 0x1d`, **`INTEGRITY_META 0x1e`**
(sealed volume), **`FEXT_TREE 0x1f`** (sealed-volume file-extent tree), `RESERVED_20 0x20`,
`TEST 0xff`, and the keybag 4CC object types `CONTAINER_KEYBAG`/`VOLUME_KEYBAG`/`MEDIA_KEYBAG`
(four-char codes, not sequential).

**File-system record types** `j_obj_types` (top 4 bits of `j_key.obj_id_and_type`,
`OBJ_TYPE_SHIFT 60`, `OBJ_ID_MASK 0x0fffffffffffffff`) — verbatim numeric values from Apple:
`SNAP_METADATA=1`, `EXTENT=2`, `INODE=3`, `XATTR=4`, `SIBLING_LINK=5`, `DSTREAM_ID=6`,
`CRYPTO_STATE=7`, `FILE_EXTENT=8`, `DIR_REC=9`, `DIR_STATS=10`, `SNAP_NAME=11`, `SIBLING_MAP=12`,
`FILE_INFO=13`.

**Checksum**: Apple states the algorithm is **Fletcher-64**; the exact arithmetic below is
**libfsapfs's** formulation (Apple's reference prose does not spell out the modular steps): Fletcher-64
over the block with the cksum field treated as zero, initial value 0;
`checksum_lower = (fl_lo + fl_hi) mod 0xffffffff`;
`checksum_upper = (fl_lo + checksum_lower) mod 0xffffffff`; `cksum = (upper << 32) | lower`.
*(Codex caveat: do NOT treat this prose formula as sufficient — land checksum **test vectors from
known real APFS objects** and cross-check against libfsapfs/`apfsck` before trusting it. A wrong
checksum implementation would make `APFS-OBJECT-CKSUM-MISMATCH` fire on every block.)*

**Key record structs** (Apple, verbatim — abbreviated):
- `j_key { u64 obj_id_and_type }` (8 B header for every fs record).
- `j_inode_val { u64 parent_id; u64 private_id; u64 create_time; u64 mod_time; u64 change_time;
  u64 access_time; u64 internal_flags; union{i32 nchildren; i32 nlink}; … xfields[] }`.
  Timestamps are **`uint64_t` nanoseconds since 1970-01-01 00:00 UTC** (disregarding leap seconds).
  *(Codex correction: Apple declares these `uint64_t`, not signed; the libfsapfs spec's "signed" for
  snapshot times is libfsapfs's own interpretation. Treat zero as a placeholder/suspicious lead with
  context, NOT as a spec-defined "unset" sentinel.)*
  **P3 offset correction (verified empirically + reconciled against TSK `istat`):** the *concrete
  on-disk byte offsets* are `parent_id@0, private_id@8, create@16, mod@24, change@32, access@40,
  internal_flags@48, nchildren/nlink@56, bsd_flags@68, owner@72, gid@76, mode@80, xfields@92`. The
  libfsapfs *asciidoc table* renders these 8 bytes later (access@48 / flags@56 / mode@86 /
  xfields@98) via a phantom gap; the offsets above match Apple's struct and the istat oracle exactly
  and are what `inode.rs` implements.
- `j_drec_val { u64 file_id; u64 date_added; u16 flags; u8 xfields[] }` (directory entry).
- `j_file_extent_val { u64 len_and_flags; u64 phys_block_num; u64 crypto_id }`;
  `J_FILE_EXTENT_LEN_MASK 0x00ffffffffffffff`, `J_FILE_EXTENT_FLAG_SHIFT 56`.
- `j_xattr_val { u16 flags; u16 xdata_len; u8 xdata[] }`; `XATTR_DATA_EMBEDDED` /
  `XATTR_DATA_STREAM` flag must be set. `com.apple.decmpfs` and `com.apple.ResourceFork` xattrs
  drive transparent compression.
- `j_snap_metadata_val { oid extentref_tree_oid; oid sblock_oid; u64 create_time; u64 change_time;
  u64 inum; u32 extentref_tree_type; u32 flags; u16 name_len; u8 name[] }`.
- `integrity_meta_phys { obj_phys_t im_o; u32 im_version; u32 im_flags; apfs_hash_type_t
  im_hash_type; u32 im_root_hash_offset; xid_t im_broken_xid; u64 im_reserved[9] }` (sealed volume).
- `inode extended field types`: `INO_EXT_TYPE_SNAP_XID=1`, `DELTA_TREE_OID=2`, `DOCUMENT_ID=3`,
  `NAME=4`, … (xfield TLVs after the fixed value).

**Keybag tags** (libfsapfs): `KB_TAG_UNKNOWN 0x00`, `KB_TAG_WRAPPING_KEY 0x01`,
`KB_TAG_VOLUME_KEY 0x02` (KEK packed object), `KB_TAG_VOLUME_UNLOCK_RECORDS 0x03` (key-bag extent),
`KB_TAG_VOLUME_PASSPHRASE_HINT 0x04`, `KB_TAG_USER_PAYLOAD 0xf8`.

**B-tree entry layout** (libfsapfs): node header is `btree_node_phys` (obj_phys + `btn_flags u16` +
`btn_level u16` + `btn_nkeys u32` + 4× `nloc_t` table/free/key-free/val-free + `btn_data[]`).
Fixed-size entry = 4 B (`key_offs u16`, `value_offs u16`); variable-size entry adds key/value lengths.
A `btree_info` footer sits at the end of a root node.

---

## 2. `apfs-core` — the reader

### 2.1 Object model and navigation primitive

APFS is **copy-on-write, transactional, and object-oriented**: everything on disk is an *object*
with a 32-byte `obj_phys_t` header carrying a Fletcher-64 checksum, an object id (`oid`), and a
transaction id (`xid`). Objects are **physical** (oid = block address), **ephemeral** (oid resolved
via the checkpoint), or **virtual** (oid resolved through an **object map / omap** at a given xid).
Navigation is therefore two-staged compared to NTFS:

```
container (NXSB) → checkpoint ring → latest valid nx_superblock (highest xid, valid cksum)
   → container omap → volume superblock (APSB) for each volume
      → volume omap (virtual-oid → paddr at xid) → root fs-tree (FSTREE)
         → j_key lookup: name → DIR_REC → inode (INODE) → data-stream (DSTREAM_ID)
            → FILE_EXTENT records → physical blocks → bytes
               → (decmpfs xattr? → decompress) → file content
```

This is the APFS analogue of NTFS `name → inode → runs → bytes`; the extra omap indirection and the
checkpoint-ring "find the live superblock" step are the APFS-specific navigation primitives.

### 2.2 Module breakdown (`core/src/`)

| Module | Owns | Key Apple structs |
|---|---|---|
| `lib.rs` | crate root, re-exports, `ApfsContainer`/`ApfsVolume` entry types, error enum | — |
| `object.rs` | `obj_phys_t` header parse, **Fletcher-64 checksum verify**, type/subtype/storage decode | `obj_phys_t`, `OBJECT_TYPE_*` |
| `container.rs` | NXSB parse, container geometry, EFI jumpstart, feature flags | `nx_superblock_t`, `nx_efi_jumpstart_t` |
| `checkpoint.rs` | descriptor + data area ring; **find latest valid superblock** (highest xid, cksum-valid); checkpoint-map resolution of ephemeral oids | `checkpoint_map_phys_t`, `checkpoint_mapping_t` |
| `omap.rs` | object map + its B-tree; **virtual-oid + xid → paddr** resolution; omap snapshots | `omap_phys_t`, `omap_key_t`, `omap_val_t` |
| `btree.rs` | generic `btree_node_phys` walker (fixed & variable entries, leaf/index, level descent), `btree_info` footer | `btree_node_phys_t`, `nloc_t`, `kvloc_t`, `btree_info_t` |
| `volume.rs` | APSB parse, volume role, **`apfs_modified_by` OS-version provenance**, volname, omap+root-tree wiring | `apfs_superblock_t`, `apfs_modified_by_t` |
| `fsrecord.rs` | `j_key` decode (oid + 4-bit type), dispatch to record value parsers; xfield (TLV) walker | `j_key_t`, `j_inode_val_t`, `j_drec_val_t`, `j_dir_stats_val_t`, `j_dstream_id_val_t`, `xf_blob_t` |
| `inode.rs` | inode value + xfields (name, dstream, doc-id, snap-xid, finder-info), timestamps (ns→`DateTime`) | `j_inode_val_t`, `INO_EXT_TYPE_*` |
| `dir.rs` | directory `DIR_REC` hashed/unhashed keys, name→file_id, **path navigation** (`name → inode`) | `j_drec_key_t`, `j_drec_hashed_key_t`, `j_drec_val_t` |
| `extent.rs` | `FILE_EXTENT` records → block list; `DSTREAM_ID`; sparse handling; **file byte read** over `Read+Seek` | `j_file_extent_val_t`, `j_dstream_t` |
| `xattr.rs` | extended attributes (embedded vs stream); symlink target; resource fork; **decmpfs detection** | `j_xattr_val_t`, `XATTR_*` flags |
| `compression.rs` | transparent compression: read `com.apple.decmpfs` header → dispatch to codec stack (REUSE) | (decmpfs reuse) |
| `snapshot.rs` | snapshot metadata tree + snap-name tree; per-snapshot extentref + sblock; **point-in-time volume view** | `j_snap_metadata_val_t`, `j_snap_name_val_t` |
| `spaceman.rs` | space manager: chunk-info blocks, allocation bitmaps, **free-queue (reaper input)** — needed for "is this block free?" deleted-record reasoning | `spaceman_phys_t`, `chunk_info_block_t`, `cib_addr_block_t` |
| `reaper.rs` | reaper state (lazy object deletion) — surfaces "deleted-but-not-yet-reaped" objects | `nx_reaper_phys_t`, `nx_reap_list_phys_t` |
| `encryption.rs` | keybag (container + volume), wrapped VEK/KEK parse, crypto-state records; **state surfacing only — no key cracking** | keybag tags, `wrapped_meta_crypto_state_t`, `j_crypto_val_t` |
| `sealed.rs` | sealed/signed system volume: **parse only** — `integrity_meta_phys`, fext-tree, file-info records (`APFS_TYPE_FILE_INFO`) and accessors. *(Codex: hash recomputation + seal validation lives in `forensic::sealed`, not here.)* | `integrity_meta_phys_t`, `fext_tree_key_t`, `fext_tree_val_t`, `j_file_info_val_t` |
| `fusion.rs` | Fusion (SSD+HDD): tier-2 device, fusion middle tree, write-back cache. **Minimal address-translation + loud `UnsupportedFusion` rejection must land in P1/P2**, since Fusion changes physical-address resolution — `core` cannot correctly read a Fusion image's files without it. Full Fusion support is later, but the *detection + fail-loud* is early. *(Codex.)* | `fusion_mt_*`, `nx_fusion_wbc_*`, `prange_t` |
| `constants.rs` | thin local re-exports / format constants not yet in forensicnomicon | (knowledge) |

**Exposed surface (consumer-facing):**
- `ApfsContainer::open<R: Read + Seek>(reader, opts) -> Result<ApfsContainer<R>>` — opens NXSB, walks
  the checkpoint ring to the **live** superblock, resolves the container omap, enumerates volumes.
- `ApfsContainer::volumes() -> impl Iterator<Item = ApfsVolume>` and `snapshots()`.
- `ApfsVolume::root() -> ApfsDir`; `ApfsVolume::open_path(&str) -> Result<ApfsInode>` (the
  name→inode navigation); `ApfsVolume::inode(oid) -> Result<ApfsInode>`.
- `ApfsInode::read_data() / read_data_at(off,len)` — assembles file extents, applies decmpfs
  transparently, returns plaintext bytes. `xattrs()`, `timestamps()`, `metadata()`.
- A **mountless, panic-free** `&[u8]`/`Read+Seek` API — no FUSE, no OS calls (FUSE is a separate
  fleet concern, `4n6mount`).
- Knowledge constants (magics, type codes, offsets) come from **`forensicnomicon`** where they
  already live or are added there (KNOWLEDGE layer), per the fleet "facts about a format →
  forensicnomicon" rule — `core` holds the *algorithms*, not the constant tables.

### 2.3 Transparent compression (REUSE, not reinvent)

APFS stores transparent compression exactly like HFS+: a `com.apple.decmpfs` xattr header
(`MAGIC 0x636d_7066` "fpmc", `HEADER_LEN 16`, `CHUNK_SIZE 65536`) whose type byte selects the codec,
with the payload either embedded in the xattr or in the `com.apple.ResourceFork` xattr / a data
stream. The fleet already solved this in `hfsplus-forensic`, validated against real macOS:

- **Type→algorithm/storage map:** `forensicnomicon::decmpfs::classify()` (`MAGIC`, `Storage`,
  `Algorithm`, `Compression`, `CHUNK_SIZE`) — depend on it; do not re-define the table.
- **zlib/DEFLATE (types 3/4):** `flate2`.
- **LZVN (types 7/8):** our **`lzvn`** crate (length-tolerant — real decmpfs LZVN blocks carry
  trailing bytes after end-of-stream that `lzfse_rust`'s strict path rejects; this was a real bug
  hfsplus-forensic hit).
- **LZFSE (types 11/12):** `lzfse_rust`.

All are pure-Rust, preserving `unsafe_code = "forbid"`. `core/src/compression.rs` is thin glue over
these; the only APFS-specific part is locating the decmpfs payload in the xattr vs resource-fork vs
dstream.

---

## 3. `apfs-forensic` — the analyzer

Mirrors `ntfs-forensic` exactly: a typed `AnomalyKind`/`Anomaly` domain enum that **keeps APFS
knowledge**, plus `audit_*()` entry points that convert each anomaly to a
`forensicnomicon::report::Finding` via `impl forensicnomicon::report::Observation` (static codes) or
an inherent `to_finding(&self, Source)` (dynamic codes). Every finding is an **observation**
("consistent with …"), never a verdict.

### 3.1 Module breakdown (`forensic/src/`)

| Module | Audits |
|---|---|
| `lib.rs` | `AnomalyKind`, `Anomaly`, `audit_container`, `audit_volume`, `audit_snapshot`, `audit_inode`; `Observation` impl |
| `integrity.rs` | checksum / structural integrity (Fletcher-64 mismatch, omap inconsistency, checkpoint anomalies) |
| `snapshots.rs` | snapshot tampering, missing/extra snapshots, xid ordering, snapshot-vs-live divergence |
| `sealed.rs` | sealed/signed-system-volume **validation**: recompute file-info hashes, compare to seal, detect `im_broken_xid` set. *(Reader-side parsing lives in `core::sealed`; this module owns the hash-recompute + finding logic — Codex's reader/analyzer split.)* |
| `recovery.rs` | recoverable deleted records (superseded objects in old checkpoints / unreaped space) |
| `crypto.rs` | encryption-state surfacing (locked volume, software-vs-hardware, keybag presence) |
| `timestamps.rs` | timestamp anomalies (Info-grade leads, like ntfs timestomp — FP-prone, deliberately Info) |
| `clones.rs` | clone/dedup analysis (`INODE_WAS_CLONED`, shared extents, dedup chains) |

### 3.2 Proposed anomaly codes (scheme-prefixed SCREAMING-KEBAB, published contract)

| Code | Category | Severity (default) | Observation |
|---|---|---|---|
| `APFS-OBJECT-CKSUM-MISMATCH` | Integrity | High | Fletcher-64 over object body ≠ stored `o_cksum` — structural corruption or tampering |
| `APFS-OMAP-INCONSISTENT` | Integrity | High | omap maps a virtual oid to a paddr whose object oid/xid/type disagrees |
| `APFS-OMAP-ORPHAN-MAPPING` | Structure | **Info** | omap entry points at a block not referable from any live tree. *(Codex: reachability across live trees + snapshots + reaper + checkpoint maps is hard to prove → Info until a complete reachability model with explicit exclusions exists; FP-prone otherwise.)* |
| `APFS-CHECKPOINT-RING-MALFORMED` | Integrity | High | descriptor/data ring **structurally** invalid: no cksum-valid superblock, bad magic, or wrap/index inconsistency. *(Codex: a plain xid gap is NOT an anomaly — xids are monotonic and the spec does not require contiguous visible checkpoints; only malformed structure is High.)* |
| `APFS-CHECKPOINT-SUPERSEDED-STATE` | History | **Info** | a non-latest checkpoint references objects absent from the latest. *(Codex: this is normal copy-on-write history, not an anomaly — framed as a recovery opportunity / residue lead, Info.)* |
| `APFS-SNAPSHOT-XID-DISORDER` | History | Info | snapshot xids not monotonically consistent with create_time ordering (a lead) |
| `APFS-SNAPSHOT-MISSING-METADATA` | Structure | Medium | snap-name tree entry without matching snap-metadata (or vice-versa) |
| `APFS-SNAPSHOT-DIVERGENCE` | History | Info | snapshot's view of an inode differs from the live volume (a lead, not an anomaly per se) |
| `APFS-SEALED-VOLUME-HASH-MISMATCH` | Integrity | High | sealed-volume file-info hash ≠ recomputed content hash. *(Codex: do NOT say "signed system volume modified" — that asserts a trust-chain conclusion. Report the hash-metadata mismatch as an observation; reserve Critical only after the canonicalization is validated against a real SSV + apfsck, since getting Apple's exact hash input wrong is itself a FP source.)* |
| `APFS-SEALED-VOLUME-BROKEN` | Integrity | High | `integrity_meta_phys.im_broken_xid` is set — seal was broken at a known transaction |
| `APFS-DELETED-INODE-RECOVERABLE` | Residue | Medium | inode/dir record superseded but still present in an older checkpoint / unreaped block |
| `APFS-DELETED-EXTENT-CARVE-CANDIDATE` | Residue | **Low** | file extent's physical blocks marked free in the spaceman bitmap → carve *candidate*. *(Codex: a free bitmap does NOT guarantee recoverable content — TRIM, encryption, zeroing, and reuse races intervene. Low, and content must be validated before any "recoverable" claim; renamed from RECOVERABLE to CARVE-CANDIDATE.)* |
| `APFS-REAPER-PENDING-OBJECT` | Residue | Low | object queued in the reaper (logically deleted, physically present) |
| `APFS-CLONE-SHARED-EXTENT` | Structure | Info | inode shares physical extents with another (clonefile/dedup) — provenance link, not an anomaly |
| `APFS-CLONE-FLAG-WITHOUT-SHARING` | Structure | Low | `INODE_WAS_CLONED` set but no shared extent found — inconsistency |
| `APFS-ENCRYPTION-LOCKED` | Concealment | Info | volume encrypted, no key available — content not readable (state, not a verdict) |
| `APFS-ENCRYPTION-STATE` | Provenance | Info | report the concrete observed keybag/crypto-state fields + flags verbatim. *(Codex: do NOT classify "software vs hardware" — that is not safely derivable from APFS on-disk structures alone; surface the raw fields and let the examiner conclude.)* |
| `APFS-ENCRYPTION-KEYBAG-ANOMALY` | Structure | Medium | keybag entry malformed or tag unexpected (`KB_TAG_*`) — show the raw tag value + offset |
| `APFS-TIMESTAMP-ZEROED` | Residue | Info | one of create/mod/change/access is 0 while siblings are set — possible wipe (Info lead) |
| `APFS-TIMESTAMP-ORDER` | Residue | Info | change_time < create_time, or access predating create — FP-prone, deliberately Info |
| `APFS-XID-REUSE` | Integrity | High | two distinct live objects claim the same `(oid,xid)` — impossible under COW, tampering-consistent |
| `APFS-ORPHAN-INODE` | Structure | Low | inode with no DIR_REC referencing it (and not in private-dir) — deleted-but-linked residue |
| `APFS-VOLUME-ROLE-MISMATCH` | Structure | Info | volume role flag inconsistent with content (e.g. SYSTEM role but unsealed) |

Notes:
- **Severity defaults** follow `Category::from_code` where the keyword classifier is right; sealed
  and checksum codes override to Critical/High explicitly.
- **"Show the unrecognized value"** (fleet robustness rule): keybag/object-type/magic anomalies MUST
  carry the raw offending bytes + offset in the `Finding` evidence (e.g. the unexpected `KB_TAG`
  value, the bad magic, the oid/xid). An "unknown" finding without the datum is non-compliant.
- New codes get new identifiers; **shipped codes never change** (published contract).

---

## 4. Validation plan (Doer-Checker)

Tier scheme (from `ntfs-forensic/docs/validation.md`):
**Tier 1** = independent third party authored both artifact and answer key, or real-world data.
**Tier 2** = real engine/tool output whose ground truth is derivable from documented construction or
an independent oracle (we chose the scenario). **Tier 3** = we authored both fixture and expected
answer (max self-deception risk — labelled, never read as Tier 1).

### 4.1 Independent oracles

*(Codex correction: oracle **independence** and corpus **tier** are orthogonal — the final tier of a
claim is `min(oracle independence, corpus provenance)`. An independent oracle run against a corpus
**we minted ourselves** yields a **Tier-2** claim; only an independent oracle on **real-world /
third-party-authored** data reaches Tier 1. This table rates oracle independence; §4.2 rates corpus
provenance; the per-capability validation entries multiply the two.)*

| Oracle | Oracle independence | Validates | Install state |
|---|---|---|---|
| **macOS itself** (`hdiutil attach -readonly`, `diskutil apfs list`, `stat`, `xattr`, `ls -lR@`) | Independent — Apple's own driver | directory tree, file bytes (post-decmpfs), timestamps, xattrs, snapshot list | present |
| **TSK `fsstat`/`fls`/`istat`** (v4.12.1) | Independent — separate C codebase | container/volume geometry, inode listing, inode metadata | **installed** |
| **`fsapfsinfo`** (libfsapfs) | Independent | NXSB/APSB fields, volume list, btree/omap, snapshot list | **must build** (LGPL — oracle only) |
| **`apfsck`** (apfsprogs) | Independent — structural fsck | checksum/omap/btree/spaceman structural integrity | **must build** |
| **apfs-fuse** | Independent | decmpfs decode + encrypted-volume unwrap on a real image | **must build** (GPL — oracle only) |
| **`apfs` / `exhume_apfs` crates** | Independent Rust | spot field cross-check | crates.io |
| In-test census (independent code path) | independent *path* (not third-party) | "we recovered exactly the snapshots/extents present" | — |

A claim is **Tier 1** only when an independent oracle above is run against a **real-world / Tier-1
corpus** (real macOS image). The same oracle on a self-minted DMG (§4.2) yields **Tier 2**.

Cross-extractor check (as ntfs does TSK-icat vs own): macOS `cp` of a decmpfs file vs our
`read_data()` must be **byte-identical** (same SHA-256), so neither extractor's assumptions are
load-bearing alone.

### 4.2 Corpora (mintable on this macOS host)

| Corpus | How minted (verbatim command → goes in corpus-catalog.md) | Tier | Tests |
|---|---|---|---|
| Plain APFS image | `hdiutil create -size 64m -fs APFS -volname APFSTEST -layout GPTSPUD apfstest.dmg` | 2 | container/volume/inode |
| With snapshots | attach → `tmutil localsnapshot` (or `diskutil apfs ...`) → detach; or `diskutil apfs addVolume` + snapshot | 2 | snapshot tree |
| decmpfs files | write large compressible files, `ditto --hfsCompression src dst` on the attached volume | 2 (macOS oracle) | compression.rs |
| Clones | `cp -c` (clonefile) on the attached volume → shared extents | 2 | clones.rs |
| Encrypted (FileVault) | `hdiutil create -encryption -stdinpass -fs APFS …` | 2 | encryption.rs (state only) |
| Sealed system volume | a real macOS system APFS image (read-only SSV) — env-gated, gitignored | 1 | sealed.rs |
| Deleted records | create+delete files between snapshots, capture image before reap | 2 | recovery.rs |
| Real macOS system images | env-gated, gitignored, documented in tests/data/README.md | 1 | end-to-end |

Per fleet standard: one repo-root `tests/data/`, large images **gitignored + env-gated** (skip
cleanly when absent), small clearly-licensed fixtures committed with provenance, and the
**verbatim minting commands** recorded in `issen/docs/corpus-catalog.md` + `tests/data/README.md`.
Recovery/carving validated against an **independent** oracle (here: macOS pre-delete capture +
`apfsck`), not only records we deleted ourselves.

---

## 5. Paranoid Gatekeeper compliance

Identical to ntfs-forensic, inherited via `[workspace.lints]`:

- **`[workspace.lints.rust] unsafe_code = "forbid"`** — pure Rust, no mmap (`Read + Seek`), no C
  bindings. (No bounded-unsafe exception needed; unlike ewf/memory-forensic we don't mmap.)
- **`[workspace.lints.clippy]`**: `all`/`pedantic` = warn, `correctness`/`suspicious` = deny,
  **`unwrap_used`/`expect_used` = deny**, with the standard pragmatic `cast_*` / `module_name_*`
  allows. Tests opt out via `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]`.
- **Panic-free, bounds-checked readers**: every integer read through a checked helper (e.g.
  `be_u32`/`le_u64` returning 0 on out-of-range, never panicking); **range-check every length /
  count / offset / oid from the image before use**; **cap allocations** (reject absurd `btn_nkeys`,
  extent counts, container sizes — allocation-bomb defense). APFS adds two specific traps to guard:
  **(a) checksum-before-trust** — verify Fletcher-64 before believing any object's fields;
  **(b) cyclic-oid defense** — omap/btree resolution must detect cycles (a malicious image can point
  an oid at itself) with a visited-set + depth cap.
- **Bootstrap-failure = fail-loud** (fleet rule): a failed *bootstrap* (NXSB not found / no valid
  superblock in the checkpoint ring / omap unresolvable) is a **loud named error**, never
  `Ok(empty)`. Degrade-to-empty is legitimate only for a per-inode miss *after* the container is
  validly opened. The "validated bootstrap" gate here: the chosen superblock must have a valid
  Fletcher-64 cksum AND `nx_magic == NX_MAGIC` before we trust it.
- **Required tooling files** (copy from ntfs-forensic, adapt metadata): `deny.toml`,
  `.gitleaks.toml`, `clippy.toml`, `rustfmt.toml`, `renovate.json`, `LICENSE` (Apache-2.0),
  `rust-toolchain.toml`.
- **Fuzzing**: `fuzz/` cargo-fuzz workspace, **one target per parsed structure** —
  `object` (obj_phys+cksum), `nx_superblock`, `checkpoint`, `omap`, `btree_node`, `fsrecord`
  (j_key dispatch), `inode`, `dir`, `extent`, `xattr`, `snapshot`, `spaceman`, `keybag`,
  `integrity_meta`, plus a **`fuzz_forensic`** target driving the full open→navigate→audit pipeline.
  Each target's invariant: "must not panic." A `fuzz.yml` builds + smoke-runs (30 s) every target.
- **CI gates** (`ci.yml`, copy ntfs-forensic's): fmt-check, `clippy --all-targets -D warnings`
  (paranoid set), test matrix, MSRV build, **100% line coverage** (`cargo llvm-cov --lib`, fail on
  any `DA:n,0` not annotated `// cov:unreachable: <invariant>`), `cargo deny`, gitleaks, fuzz-check,
  docs (`RUSTDOCFLAGS=-D warnings cargo doc`).
- **MSRV**: low published-library MSRV per fleet policy. hfsplus-forensic pins `1.85`; match it
  (`rust-version = "1.85"`) and CI-verify with an MSRV build job. `rust-toolchain.toml` pins the
  current fleet stable for dev. **Both crates are published libraries → keep MSRV low and verified.**
- **README + mkdocs + docs/validation.md** per the SecurityRonin README standard (two-row badge
  block: crates.io ×2 / docs.rs / MSRV / Apache-2.0 / Sponsor — then CI / Coverage / unsafe-forbidden
  / security-audit), MkDocs site with `docs.yml` deploying to Pages, `docs/privacy.md` +
  `docs/terms.md` backing the footer links, `docs/validation.md` with the tiered evidence.

---

## 6. Phased implementation roadmap

Each milestone lands RED tests first, then GREEN, with its oracle. (TDD: separate RED/GREEN commits.)

| Phase | Deliverable | Primary oracle |
|---|---|---|
| **P0** | scaffold, workspace, lints, tooling, CI skeleton (this commit) | `cargo build` |
| **P1** | `object.rs` + `container.rs` + `checkpoint.rs`: open NXSB, **Fletcher-64 verify**, walk checkpoint ring to the live superblock, read container geometry | `fsstat` geometry; `fsapfsinfo` NXSB fields |
| **P2** | `omap.rs` + `btree.rs`: generic btree walk + virtual-oid→paddr resolution (with cycle/alloc caps) | `apfsck` structural; `fsapfsinfo` btree/omap |
| **P3 ✅** | `volume.rs` + `fsrecord.rs` + `inode.rs` + `dir.rs`: APSB, j_key dispatch, inode metadata, **name→inode path navigation** — DONE (validated vs TSK `fls`/`istat` on the self-minted `apfs_fstree.bin`; inode offsets corrected — see §1.2) | `fls`/`istat`; macOS `stat` |
| **P4** | `extent.rs` + `compression.rs` + `xattr.rs`: file byte read, decmpfs (REUSE codecs), symlinks/resource-fork | macOS `cp` byte-identical (SHA-256); apfs-fuse |
| **P5** | `snapshot.rs`: snapshot metadata + name trees, point-in-time volume view | `tmutil`/`diskutil apfs listSnapshots`; fsapfsinfo |
| **P6** | `spaceman.rs` + `reaper.rs`: allocation bitmaps, free-queue, deleted-but-unreaped surfacing | `apfsck` spaceman |
| **P7** | `encryption.rs`: keybag + crypto-state parse, **state surfacing only** | apfs-fuse keybag; macOS `diskutil apfs` |
| **P8** | `sealed.rs` + `fusion.rs`: integrity_meta + file-info hashes; Fusion middle tree | real SSV image; `apfsck` |
| **P9** | `apfs-forensic` analyzer: all anomaly codes wired to `audit_*` + `Observation` | end-to-end on minted + real corpora |
| **P10** | fuzz targets, 100% coverage, README/mkdocs/validation.md, publish prep | CI gates |

Crypto note: **never crack keys or hand-roll crypto.** Encryption work is *state surfacing* and
(if a passphrase/key is supplied) *unwrapping via a vetted crate* (RustCrypto `aes`/`hmac`/PBKDF2 /
the AES-XTS the spec uses). No placeholder crypto — if a key isn't available, the reader **refuses**
to return plaintext (names what it can't do), never fabricates.

---

## 7. Fleet placement

- **Layer:** FILESYSTEM. `apfs-forensic [planned]` is already listed in `issen/CLAUDE.md`'s layer map
  next to `ntfs-forensic` and `ext4fs-forensic`.
- **Dependency direction:** depends DOWN on **KNOWLEDGE** (`forensicnomicon` for magics/type
  codes/decmpfs map + the `report` model) and on the decmpfs codec crates (`lzfse_rust`, our `lzvn`,
  `flate2`). Consumes a CONTAINER sector stream (`Read + Seek`) — typically from `dmg`/`dd`/`ewf`/
  raw — exactly like ntfs-forensic. **Never** imports CONTAINER/PAGING/OS-STRUCTURE crates.
- **Consumers (upward):** Issen ORCHESTRATION wires `apfs-core` for navigation and
  `apfs-forensic` findings into the unified `Report`/timeline; `4n6mount` can expose an
  `ApfsContainer` over FUSE (separate repo, not this one). `apfs-forensic` accepts `Read+Seek` or
  `&[u8]` and is medium-agnostic (PARSER-style boundary), so a memory-carved APFS block can be
  audited without a container.
- **Crate naming (Pattern A):** `apfs-core` (reader, `[lib] name = "apfs_core"` to avoid hijacking
  the existing third-party `apfs` crate's import path — that crate is popular-enough/extant, so we
  keep the `_core` import like ntfs-core does for Colin Finck's `ntfs`) + `apfs-forensic` (analyzer).
  **[DECISION NEEDED — see §8.]**

---

## 8. Decisions and open items

### 8.1 Resolved (2026-06-21)

1. **Build `apfs-core` from scratch; do not reuse the `apfs` crate as the reader, do not acquire the
   bare name.** The existing `apfs` crate (Dil4rd/dpp, read-only, 771 downloads) was evaluated for
   sufficiency and is **not** enough: it has **no Fletcher-64 checksum** verification and **zero
   sealed-volume / integrity** support — exactly the structures `apfs-forensic`'s
   `APFS-OBJECT-CKSUM-MISMATCH` and `APFS-SEALED-VOLUME-*` codes depend on — and it uses `unsafe`
   (5 sites), failing the fleet `forbid(unsafe_code)` bar for attacker-controlled images. This is the
   `ntfs` precedent exactly (we keep `ntfs_core` rather than hijack Colin Finck's popular `ntfs`
   crate, for the same forensic-internals + panic-hardening reasons). Publish `apfs-core` with
   `[lib] name = "apfs_core"`, import as `apfs_core::…`; keep the `apfs` crate as **one Tier-2
   cross-check oracle** (§4.1), never a dependency.
2. **Repo published to GitHub `SecurityRonin/apfs-forensic` (public, Apache-2.0)** on 2026-06-21, as a
   design + skeleton scaffold ahead of implementation, using the fleet README/metadata/Pages standard.
3. **Encryption scope: state-surfacing + optional unwrap-with-supplied-key only.** No brute force, no
   key recovery; FileVault is not decrypted without a supplied key. `APFS-ENCRYPTION-*` codes surface
   the encryption *state* (keybag presence, wrapped-key class, software vs hardware) as observations.
4. **Oracles build into a gitignored `tools/` on the dev host** (`fsapfsinfo`, `apfsck`, `apfs-fuse`
   — GPL/LGPL, oracle-only, **never linked**). Data-sourcing preference, fleet-wide and binding for
   this crate: **real data > synthetic > and document provenance in every case** (real macOS / SSV
   images preferred; `hdiutil`/`ditto`/`tmutil`-minted artifacts next; both recorded in
   `tests/data/README.md` with verbatim generators + the oracle output).
5. **Sealed-volume hash (`im_hash_type` / SSV seal) is implemented LAST (phase P8)** and validated
   **only** against a real SSV image + `apfsck` — never a synthetic seal we compute ourselves
   (the canonicalization is the least-documented area; a self-authored seal is the Tier-3 LZNT1 trap).
   `APFS-SEALED-VOLUME-HASH-MISMATCH` ships only once that real-data validation exists.
6. **Snapshot codes stay observation leads.** `APFS-SNAPSHOT-*` are framed Info/Medium and worded
   "consistent with", never as proof — legitimate operations (Time Machine thinning) produce similar
   signatures, so the analyst/tribunal draws the conclusion (fleet expert-witness discipline).

### 8.2 Open — resolve at implementation time

- **decmpfs codec source**: reuse `forensicnomicon::decmpfs` (registry) once its decmpfs module is
  published at a pinnable version, else a path dep during a coordinated change (as hfsplus did).
  Confirm/pin the published version when phase P4 (extents + transparent compression) starts.
- **`ER_MAGIC` and a few flag enums** are marked **[UNVERIFIED]** in §1.2 — confirm each verbatim
  against the Apple File System Reference at implementation time rather than trusting this doc.

---

## Appendix A — Codex review

One adversarial critique round was run (Codex `gpt-5.5`, `codex exec`, read-only sandbox) against
the draft. Codex's spec claims were **independently re-verified against the on-disk Apple APFS
Reference** (`pdftotext` extract) before applying — Codex can also be wrong, but every verifiable
point below checked out. 15 findings; resolution:

| # | Codex finding | Verified? | Resolution |
|---|---|---|---|
| Spec | NX_MAGIC/APFS_MAGIC/obj_phys 32 B/`OBJ_TYPE_SHIFT 60`/types 1–13/Fletcher-64 all correct | ✓ (confirmed vs Apple) | No change — Codex confirmed the core claims |
| 1 | Object-type list truncated — missing `0x1b`–`0x20` + keybag types | ✓ (Apple lines 1119–1157) | **Fixed**: list completed, `INTEGRITY_META 0x1e` / `FEXT_TREE 0x1f` added, "verbatim" qualified |
| 2 | Inode timestamps are `uint64_t`, not signed; 0 ≠ spec "unset" | ✓ (Apple line 4365) | **Fixed**: corrected to `uint64_t`; zero is a contextual lead, not a sentinel |
| 3 | `ER_MAGIC` is defined: `'FLAB'` | ✓ (Apple line 10098) | **Fixed**: `ER_MAGIC 'FLAB'`, LE `0x464C4142` |
| 4 | Fletcher-64 prose formula needs test-vector verification | ✓ (Apple gives algorithm name only) | **Fixed**: added caveat — land real-object test vectors before trusting |
| — | `fext_tree_*` is shorthand; real types are `fext_tree_key_t`/`val_t` | ✓ (Apple lines 8852/8877) | **Fixed**: named explicitly |
| 5 | `sealed.rs` mixes reader + analyzer | valid (design judgment) | **Fixed**: `core::sealed` = parse/accessors; `forensic::sealed` = hash-recompute + findings |
| 6 | Fusion scheduled too late — it affects physical addressing | valid | **Fixed**: minimal Fusion translation + loud `UnsupportedFusion` rejection moved to P1/P2 |
| 7 | Oracle Tier 1 over-labeled for self-minted corpora | valid (own tier scheme) | **Fixed**: split oracle-independence from corpus-tier; self-minted ⇒ Tier 2 |
| 8 | Deleted-record validation not independent if author-controlled | valid | **Fixed**: labelled Tier 2; real images required for Tier-1 recovery claims |
| 9 | `xid gap` as High anomaly too strong | valid (xids monotonic, gaps normal) | **Fixed**: renamed to `CHECKPOINT-RING-MALFORMED`, only structural malformation is High |
| 10 | "non-latest checkpoint refs absent objects" is normal COW | valid | **Fixed**: `CHECKPOINT-SUPERSEDED-STATE`, Info, framed as residue/recovery |
| 11 | `OMAP-ORPHAN-MAPPING` FP-prone without reachability model | valid | **Fixed**: dropped to Info pending a complete reachability model |
| 12 | `SEALED-VOLUME-MISMATCH` overstates "modified" (trust-chain) | valid | **Fixed**: `HASH-MISMATCH`, High not Critical, "hash-metadata mismatch" wording |
| 13 | Free spaceman bitmap ≠ recoverable (TRIM/encryption/reuse) | valid | **Fixed**: `CARVE-CANDIDATE`, Low, content-validation required |
| 14 | `ENCRYPTION-SOFTWARE` overclaims software-vs-hardware | valid | **Fixed**: `ENCRYPTION-STATE`, report raw fields only |
| 15 | Missing prior art: mac_apt, pyfsapfs/dfVFS | valid | **Fixed**: added to prior-art table as oracle/study references |

**Where Codex was imprecise (cross-checked, not blindly applied):** Codex listed `RESERVED_20 0x20`
and a `keybag 4CC` set as if fully enumerated; the Apple reference confirms `RESERVED_20 0x20`,
`INVALID 0x0`, `TEST 0xff`, and `CONTAINER/VOLUME/MEDIA_KEYBAG` as four-char-code object types — so
Codex was directionally right but I verified each value rather than copying its list. No finding was
applied without confirming against the primary source.

No second round was needed: round 1's findings were either spec corrections (now verified + applied)
or severity/wording de-escalations (applied), with no remaining substantive architectural dispute.
