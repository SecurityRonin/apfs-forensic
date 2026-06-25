# Validation

> **Status: phases P1–P5 validated (Tier 2).** Results are recorded here as each
> phase lands; later phases (spaceman, encryption, sealed) are still in progress.
> Claims below are scoped to the validated capabilities and tiered.

## How to read the evidence tiers

- **Tier 1** — an independent third party authored both the artifact and the
  answer key, or the data is real-world.
- **Tier 2** — real engine/tool output whose ground truth is derivable from the
  documented construction or confirmed by an independent oracle, but we chose the
  scenario (so it can miss real-world quirks).
- **Tier 3** — we authored both the fixture and the expected answer with nothing
  independent vouching (maximal self-deception risk; labelled, never read as
  Tier 1).

**Oracle independence and corpus tier are orthogonal.** The tier of a claim is
`min(oracle independence, corpus provenance)`: an independent oracle run against a
corpus we minted ourselves is **Tier 2**; only an independent oracle on real-world
data reaches **Tier 1**.

## Independent oracles

| Oracle | Independence | Validates | Install |
|---|---|---|---|
| **macOS** (`hdiutil attach -readonly`, `diskutil apfs list`, `stat`, `xattr`, `ls -lR@`) | Apple's own driver | directory tree, file bytes (post-decmpfs), timestamps, xattrs, snapshots | present |
| **The Sleuth Kit** `fsstat`/`fls`/`istat` (v4.12.1) | separate C codebase | container/volume geometry, inode listing + metadata | installed |
| **`fsapfsinfo`** (libfsapfs) | independent | NXSB/APSB fields, volumes, btree/omap, snapshots | build (LGPL — oracle only) |
| **`apfsck`** (apfsprogs) | structural fsck | checksum/omap/btree/spaceman structural integrity | build |
| **apfs-fuse** | independent | decmpfs decode + encrypted-volume unwrap | build (GPL — oracle only) |
| **`apfs` / `exhume_apfs` crates** | independent Rust | spot field cross-check | crates.io |

Cross-extractor check: macOS `cp` of a decmpfs file vs `apfs-core::extent::read_data`
must be byte-identical (same SHA-256), so neither extractor's assumptions are
load-bearing alone.

## Corpora (mintable on a macOS host)

| Corpus | Mint command | Tier |
|---|---|---|
| Plain APFS | `hdiutil create -size 64m -fs APFS -volname APFSTEST -layout GPTSPUD apfstest.dmg` | 2 |
| Snapshots | attach → `tmutil localsnapshot` / `diskutil apfs` → detach | 2 |
| decmpfs | `ditto --hfsCompression src dst` on the attached volume | 2 (macOS oracle) |
| Clones | `cp -c` (clonefile) on the attached volume | 2 |
| Encrypted | `hdiutil create -encryption -stdinpass -fs APFS …` | 2 |
| Sealed system volume | real macOS SSV image (env-gated, gitignored) | 1 |
| Real macOS images | env-gated, gitignored | 1 |

Verbatim mint commands are recorded in `issen/docs/corpus-catalog.md` and
`tests/data/README.md`. Carving/recovery is validated against an **independent**
oracle (real images / pre-delete capture + apfsck), not only records we deleted
ourselves.

## Validated capabilities

### Object map + B-tree navigation + volume-superblock resolution (P2) — Tier 2

**Corpus:** `tests/data/apfs_container_chain.bin` — blocks 0–344 (1.38 MiB) of a
real APFS *container partition* minted by Apple's own `hdiutil`
(`hdiutil create -size 128m -fs APFS -volname APFSORACLE -layout GPTSPUD`). The
slice holds the complete checkpoint ring **and** the full
NXSB → container omap → omap B-tree → volume superblock (APSB) chain. Because the
carve starts at NXSB block 0, a physical block address maps directly to
`paddr * 4096` in the fixture. Provenance + MD5 in `tests/data/README.md`.

**What is exercised** (`core/tests/{omap,btree,btree_descend,volume_resolve}.rs`):

| Claim | Evidence | Oracle |
|---|---|---|
| `omap_phys_t` header decode (`om_flags`/`om_tree_type`/`om_tree_oid`/`om_snapshot_tree_oid`) | `nx_omap_oid = 343` → `om_tree_oid = 344`, `om_flags = OMAP_MANUALLY_MANAGED` | offsets verified verbatim vs the Apple reference + libfsapfs; raw-image decode |
| `btree_node_phys_t` header + TOC iterate (fixed + variable KV) | omap root @344: `btn_flags = 0x7` (ROOT\|LEAF\|FIXED), 1 fixed entry `omap_key(1026,2)` → `omap_val(paddr 342)` | Apple reference + libfsapfs spec (4-byte `kvoff_t`, 8-byte `kvloc_t`, `btree_info` footer) |
| Root→leaf descent with cksum + cycle guards | real omap walk yields exactly `(1026, 2, 342)`; a corrupted node fails Fletcher-64 (`ChecksumMismatch`); a self-referential index node trips `CycleGuard` | construction; checksum-before-trust |
| Virtual `nx_fs_oid` → physical APSB paddr | `volume_superblock_addrs() == [342]`; block 342 carries APSB magic `0x42535041` + valid Fletcher-64 | **Apple `diskutil apfs list`** and **libfsapfs `fsapfsinfo`** (run on the committed fixture) each report **exactly one volume** (`APFSORACLE`) — matching the single resolved APSB |

**Independence:** `fsapfsinfo` (libfsapfs, a separate C codebase) reads the exact
committed `apfs_container_chain.bin` and reports `Number of volumes: 1`, volume
identifier `fa8b74aa-…`, name `APFSORACLE` — matching Apple `diskutil`. The
B-tree TOC and value offsets were verified verbatim against the Apple *APFS
Reference* and the libfsapfs format spec before implementation, not from memory.

**Tier rationale:** independent oracle (libfsapfs/diskutil) on a **self-minted**
corpus ⇒ Tier 2 (`min(independent, self-minted)`). A Tier-1 lift needs the same
resolution run on a real-world / third-party image (env-gated, future work).

### Volume superblock + fs-record dispatch + inode metadata + name→inode (P3) — Tier 2

**Corpus:** `tests/data/apfs_fstree.bin` — blocks 0–373 (1.46 MiB) of a real APFS
*container partition* minted by Apple's own `hdiutil`
(`hdiutil create -size 128m -fs APFS -volname APFSP3 -layout GPTSPUD`), populated
with a **known directory tree** before carving. The slice reaches the full chain
NXSB → checkpoint → container omap → APSB (block 371) → volume omap (366/367) →
the virtual file-system tree leaf node (block 365). Provenance + the known-tree
table + MD5 in `tests/data/README.md`.

**What is exercised** (`core/tests/{volume,fsrecord,inode,dir}.rs`):

| Claim | Evidence | Oracle |
|---|---|---|
| `apfs_superblock_t` (APSB) decode | block 371: magic `APSB`, `apfs_fs_index = 0`, `apfs_omap_oid = 366`, `apfs_root_tree_oid = 1028` (virtual), volname `APFSP3` | offsets verbatim vs libfsapfs `fsapfs_volume_superblock`; **TSK `pstat`** reports APSB block 371, oid 1026, xid 6, volume `APFSP3` |
| `j_key` dispatch + `xf_blob` TLV walk | top-4-bit type / low-60-bit oid split; xfields decode NAME + DSTREAM with 8-byte value alignment | Apple reference + libfsapfs format spec |
| `j_inode_val_t` metadata | Beth.txt (inode 20): parent 18, size 38, mode 0644, uid/gid 99, create `1782060082608648902`, mod `…686902`, access `…733745215`; root (2): mode 0755, uid 501, 3 children | **TSK `istat -o 40 -B 371`** — every field (size, mode, uid/gid, child/link count, all four ns-timestamps) matches per inode |
| **name→inode path navigation** | `open_path` resolves `/top.txt`→22 (15 B), `/Dir1/Beth.txt`→20 (38 B), `/Dir1/Sub/secret.bin`→21 (26 B); `/`→root(2); `//` and trailing `/` normalize; missing components error loudly | **TSK `fls -r -o 40 -B 371`** lists the identical tree + inode numbers; macOS `stat` confirmed sizes pre-detach |

**Inode-offset correction (vs the design doc).** The design doc placed the inode
timestamps/mode following the libfsapfs *asciidoc table* (access@48, flags@56,
nchildren@64, mode@86, xfields@98). The real on-disk `j_inode_val_t` — verified
empirically and reconciled against TSK `istat` (timestamps + mode + uid for inode
20/2) — has these fields **8 bytes earlier**: access@40, internal_flags@48,
nchildren/nlink@56, bsd_flags@68, owner@72, gid@76, mode@80, **xfields@92**. The
asciidoc table inserts a phantom 8-byte gap; the empirical layout matches Apple's
struct and the istat oracle exactly. `inode.rs` uses the corrected offsets.

**fs-tree is virtual.** The fs-tree's node oids resolve through the **volume**
object map (`ObjectMap::resolve`) at the volume xid; `dir::for_each_fs_record`
walks it with checksum-before-trust, a visited-set cycle guard, and a depth cap.
The fixture's fs-tree is a single leaf, so the index-node descent and cycle guard
are exercised on a synthetic two-level virtual tree (valid Fletcher-64), mirroring
the P2 `btree_descend.rs` pattern — every *functional* assertion uses the real
fixture + TSK oracle.

**Tier rationale:** independent oracle (TSK `fls`/`istat`, a separate C codebase)
on a **self-minted** corpus ⇒ Tier 2. A Tier-1 lift needs the same navigation run
on a real-world macOS image (env-gated, future work).

### File byte read + decmpfs + xattr + symlink (P4) — Tier 2

**Corpus:** `tests/data/apfs_content.bin` — the first **442 blocks** (1.73 MiB,
4096-byte blocks) of a real APFS *container partition* minted by Apple's own
`hdiutil` (`hdiutil create -size 128m -fs APFS -volname APFSP4 -layout GPTSPUD`),
populated with **known content covering every read path**: a plain file, a
**sparse** file (a 64 KiB hole + a tail extent), a **transparently-compressed**
file (`ditto --hfsCompression` → decmpfs **type 8, LZVN, resource fork**), a file
with **custom xattrs**, and a **symlink**. The carve reaches the full chain
NXSB → checkpoint → container omap → live APSB (block 438, xid 14) → volume omap
(433/434) → fs-tree leaf (block 432) **and** every file's data extents +
resource fork (blocks 345–426). Provenance + MD5 in `tests/data/README.md`.

**What is exercised** (`core/tests/{extent,compression,xattr}.rs`):

| Claim | Evidence | Oracle |
|---|---|---|
| **plain-file extent assembly** | `/plain.txt` (35 B, single extent phys 347) reads back byte-identical | **macOS `shasum -a 256`** = `289af0a0…` (matches `read_data`) |
| **sparse-hole handling** | `/sparse.bin` (69632 B): `FILE_EXTENT` records are a 64 KiB hole (`phys_block_num 0`) + a 4 KiB tail @65536; the hole reads back as zeroes | **macOS `cp`** SHA-256 = `fe0fc4fa…`; `list_extents` surfaces the raw hole+tail |
| **nested-file read** | `/Dir1/Beth.txt` (33 B, phys 400) | **macOS** SHA-256 = `ee7c2682…` |
| **decmpfs type-8 LZVN (resource fork)** | `/compressed.txt` (180000 B): `com.apple.decmpfs` header (type 8) + a `com.apple.ResourceFork` **stream** xattr (dstream 24, 1526 B, three LZVN chunks); decoded transparently by `read_data` | **macOS `cp`** SHA-256 = `3f58a418…` — identical to our decoded output (the cross-extractor check) |
| **decmpfs other types** | inline 1/9, zlib 3 (+0xFF-stored), LZVN 7 (real chunk + 0x06-stored), LZFSE 11, resource-fork zlib 4 / LZFSE 12 / uncompressed 10 | `forensicnomicon::decmpfs::classify` + `flate2`/`lzvn`/`lzfse_rust`; round-trip / real-chunk |
| **decmpfs refusals (fail-loud)** | bad magic, truncated, unknown type, dedup type 5, LZBitmap 13/14, missing fork, length mismatch all return a named `ApfsError::Decmpfs` — never fabricated bytes | construction |
| **extended attributes** | `/plain.txt` carries `com.example.tag`="forensic-marker-P4", `user.note`="second custom attr" (both embedded) | **macOS `xattr -l`** — names + values match `list_xattrs` |
| **symlink target** | `/symlink_to_beth` → `com.apple.fs.symlink` (embedded) = `"Dir1/Beth.txt"` | **macOS `readlink`** = `Dir1/Beth.txt` |

**SHA-256 oracle reconciliation (the byte-identical cross-extractor check).** Each
file's content, as assembled by `apfs_core::extent::read_data`, hashes identically
to the macOS-read bytes captured before detach:

| File | Bytes | `apfs_core::read_data` SHA-256 | macOS `shasum -a 256` | Match |
|---|---|---|---|---|
| `/plain.txt` | 35 | `289af0a0…abf86b` | `289af0a0…abf86b` | ✅ |
| `/sparse.bin` | 69632 | `fe0fc4fa…cc822a` | `fe0fc4fa…cc822a` | ✅ |
| `/Dir1/Beth.txt` | 33 | `ee7c2682…cfeb96` | `ee7c2682…cfeb96` | ✅ |
| `/compressed.txt` (decompressed) | 180000 | `3f58a418…3abc78` | `3f58a418…3abc78` | ✅ |

**decmpfs codec reuse (not reinvented).** `core/src/compression.rs` is thin glue
over the fleet's validated codec stack — `forensicnomicon::decmpfs::classify` for
the type→algorithm/storage map, `flate2` (zlib 3/4), our length-tolerant
`lzvn` (`lzvn-core`, types 7/8 — the decoder hfsplus-forensic validated 25/25 on
real macOS Tahoe data, tolerant of the trailing bytes that `lzfse_rust`'s strict
path rejects), and `lzfse_rust` (types 11/12). The only APFS-specific logic is
locating the payload (inline xattr vs `com.apple.ResourceFork` stream).

**Symlink-target source (verified, not assumed).** Empirically the symlink target
is the **embedded** `com.apple.fs.symlink` xattr value (flags `0x6` =
`EMBEDDED | 0x4`, value `"Dir1/Beth.txt\0"`), confirmed against the raw fixture
and macOS `readlink`. (APFS does also store it as a data stream; the xattr form is
what `ditto`/`ln -s` produced here and what the reader resolves.)

**Tier rationale:** independent oracle (macOS `cp`/`xattr`/`readlink`, Apple's own
driver, plus the documented construction) on a **self-minted** corpus ⇒ Tier 2
(`min(independent, self-minted)`). The decmpfs decoder additionally inherits
hfsplus-forensic's real-macOS validation of the same codec stack. A Tier-1 lift
needs the same reads run on a real-world macOS image (env-gated, future work).

### Snapshots + point-in-time volume view (P5) — Tier 2 (+ env-gated populated path)

**What P5 reads.** A volume's snapshots live in a single B-tree located by the
APSB's **physical** `apfs_snap_meta_tree_oid` block number (offset 152;
libfsapfs names it `snapshot_metadata_tree_block_number`, `o_subtype` 0x10
`SNAPMETATREE`). The tree is variable-KV and holds two record kinds dispatched by
the `j_key` top-4-bit type: **metadata** (`SNAP_METADATA 1`, keyed by the
snapshot **xid**, value `j_snap_metadata_val_t`) and **name** (`SNAP_NAME 11`,
keyed by name, value `j_snap_name_val_t { snap_xid }`). `mount_snapshot` reads a
snapshot's `sblock_oid` (a physical APSB block) and **grafts the live volume's
object map** onto the frozen superblock: a snapshot's own `apfs_omap_oid` is `0`,
so its fs-tree is read through the live omap, resolving oids at the snapshot's
xid (`ok_xid ≤ snapshot_xid`). The existing P3/P4 navigation then reads the
volume exactly as it stood at snapshot time.

**Constant verification (before coding).** The `j_snap_metadata_val_t` field
offsets were taken **verbatim** from libfsapfs `fsapfs_snapshot_metadata_btree_value`
*and* independently cross-confirmed against dissect.apfs `j_snap_metadata_val`;
both agree exactly: `extentref_tree_oid@0, sblock_oid@8, create_time@16,
change_time@24, inum@32, extentref_tree_type@40, flags@44, name_len@48, name@50`.
A RED unit test caught an early off-by-2 (name placed at @48 instead of @50,
mis-reading `flags@44` as ending at @46) — the offsets above are what `snapshot.rs`
implements and what the unit test now asserts.

**What is exercised** (`core/tests/snapshot.rs` + `core/src/snapshot.rs` units):

| Claim | Evidence | Oracle / tier |
|---|---|---|
| **snap-meta tree located + walked on real Apple bytes** | the P4 fixture's APSB (block 438) carries `apfs_snap_meta_tree_oid` = block 340, a real `o_subtype 0x10` btree node whose `btn_nkeys` is 0; the walk reads it, **verifies its Fletcher-64 checksum**, and returns zero snapshots | the documented empty tree + Apple-authored checksum (**Tier 2**, real structure) |
| **`j_snap_metadata_val_t` decode** | every field decoded at the verified offsets | libfsapfs + dissect.apfs agreement (constant verification) |
| **`j_snap_name_key_t` decode + name→xid resolve** | `resolve_snapshot_xid` returns `None` on the empty real tree; returns the right xid on a populated vector | construction + the libfsapfs `snap_xid` value layout |
| **point-in-time seam** | `mount_snapshot` reads `sblock_oid` as an `ApfsVolume` and grafts the live omap (a snapshot's own `apfs_omap_oid` is `0`); the frozen `root_tree_oid`/`xid` are preserved. A unit test pins the graft (`omap_oid` overridden to the live volume's); mounting a non-APSB block (NXSB @0) **fails loudly** with `UnexpectedObjectType` | real P4 APSB + `omap_oid==0` contract (**Tier 2**) |
| **walk control flow** (leaf dispatch, index-node **virtual** child descent through the volume omap, checksum-mismatch fail-loud, visited-set cycle guard) | spec-faithful hand-built APFS micro-images: real `obj_phys` headers, real Fletcher-64, real variable-KV TOC/key/value + fixed-KV omap layout | **Tier 3** (walk control flow only; every offset/decode it relies on is Tier-2-validated on real data above) |

**Populated changing-file path (env-gated) — VALIDATED on real snapshots.** The
**v1-vs-v2 point-in-time read** (read `changing.txt` at the earliest snapshot →
v1 SHA-256; at the live volume → v2 SHA-256; assert each matches what macOS
wrote, and that they differ) ran from
`core/tests/snapshot.rs::populated_fixture_point_in_time_read` against a real
Apple-minted fixture and **passed** — byte-identical to the macOS oracle
(v1 `da27342b…`, v2 `cfd0476c…`; snapshot XIDs 6094/6096). This is the strongest
P5 evidence: an independent oracle (macOS itself) on real snapshots, and it
caught a real bug the synthetic seam test missed — the committed `mount_snapshot`
did not graft the live omap, so point-in-time `open_path` read block 0 (the NXSB)
and failed. The fixture is a whole GPT disk image (a Tart VM `disk.img`); the
test opens it through a partition-offset view and **derives** the live APSB from
the container omap. Gated on `APFS_P5_FIXTURE` (+ `APFS_P5_PART_OFFSET`,
`APFS_P5_FILE`, `APFS_P5_V1_SHA256`, `APFS_P5_V2_SHA256`); **skips cleanly** when
absent. See `tests/data/README.md` for the mint recipe and recorded values.

> **Performance (keyed descent, two layers).** Navigation was quadratic on real
> volumes; two keyed-descent changes fixed it, each measured on the real P5
> fixture:
>
> 1. **omap** (`btree::find_leaf`): `omap.resolve` reads one root→leaf path
>    instead of scanning the whole omap B-tree on every node resolution. Cut the
>    point-in-time validation run from **~4962 s (~83 min) to ~5 s**.
> 2. **fs-tree** (`dir::for_each_fs_record_for_oid`): the fs-tree walk now prunes
>    to the target object id — at each index node it descends only children whose
>    key range can cover that oid (`child_may_contain_oid`), instead of visiting
>    every node and filtering. Every navigation entry point (`lookup_child`,
>    `load_inode`, `list_dir`, `list_extents`, `list_xattrs`) keys by one object
>    id, so all benefit.
>
> **Measured (env-gated `keyed_nav.rs::keyed_navigation_prunes_real_fs_tree`, real
> macOS multi-level fs-tree):** resolving + reading `/Users/admin/changing.txt`
> touched **25 955 distinct blocks before → 26 after** the fs-tree pruning, same
> byte-identical bytes (the macOS `APFS_P5_V2_SHA256` oracle). With both layers
> the point-in-time test runs in **~0.01 s** (from ~83 min). The committed
> fixtures are single-leaf, so the index-pruning branch is validated on the real
> multi-level tree (above) plus a CI-visible cross-check that the keyed walk
> returns the same record set as the full unpruned walk on `apfs_fstree.bin`
> (`dir::tests::keyed_walk_matches_full_walk_on_real_fs_tree`) and a boundary-case
> unit test of the prune predicate (`child_pruning_selects_only_covering_subtrees`).

> **Minting blocker (host capability, documented).** Creating an APFS snapshot on
> an arbitrary (DMG) volume requires the `com.apple.developer.vfs.snapshot`
> entitlement: under SIP, `fs_snapshot_create(2)` returns **`EPERM` even as root**,
> `diskutil apfs` has no `addSnapshot` verb, and `tmutil localsnapshot` only
> snapshots the Time-Machine-eligible system data volume (never the DMG). The
> only entitled creator on a stock host is `tmutil`, which cannot target a DMG.
> So the populated `changing.txt` fixture is minted on a host where snapshot
> creation is permitted (SIP-relaxed dev box, or a TM-registered volume); the
> exact mint commands are recorded in `tests/data/README.md` and
> `issen/docs/corpus-catalog.md`. The location, empty-case, decode, point-in-time
> seam, and walk control flow are all validated **now** on real Apple bytes +
> spec-faithful vectors per the table above.

**Tier rationale:** independent structure (Apple's own snap-meta tree + Fletcher-64)
on a self-minted corpus ⇒ Tier 2 for the location/empty/seam claims; the populated
v1-vs-v2 path lifts to Tier 2 with an independent oracle (`diskutil apfs
listSnapshots` + macOS-written SHA-256) once the env-gated fixture is supplied.
