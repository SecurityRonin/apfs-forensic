# APFS-native FileVault test data

## `apfs-native-filevault.raw.gz`

A real APFS container holding one **software-encrypted (APFS-native) volume**,
minted on macOS by Apple's own implementation. Not synthetic, and not a
hand-built structure.

| | |
|---|---|
| Source | self-minted on macOS 27.0 (see recipe below) |
| Password | `apfs-FV-TEST-2026` |
| Volume | `FVTEST`, case-insensitive, 128 MB container |
| Plaintext marker | `APFS-FILEVAULT-GROUND-TRUTH-MARKER-0123456789` in `/marker.txt` |
| Compressed | 166,731 bytes (raw 134,176,768) |
| MD5 (`.gz`) | `31f9d1fad5f16408d5f15205e250a3c1` |
| SHA-256 (`.gz`) | `47b39e2f3c3bb806cc8587edf0479fc7ff6695ca59cdea58c5adb387273fbe49` |
| Tier | **2** — real artifact from an independent implementation (Apple), ground truth known by construction |
| Redistribution | ours; contains no third-party content |

### Why this fixture exists

It is the difference between testing the decryption chain and testing nothing.
Every value in it — keybag, wrapped KEK, salt, iteration count, VEK, AES-XTS
ciphertext — was produced by macOS, so a decoder that agrees with it agrees with
Apple rather than with itself.

### The trap this fixture avoids

**`hdiutil create -encryption AES-256 -fs APFS` does NOT produce an
APFS-encrypted volume.** It encrypts the *disk image wrapper* (UDIF). Attach it
with the password and the APFS inside is plain — `NXSB`/`APSB` visible at ~0
bits/byte entropy. A decryption implementation validated against such an image
is validated against nothing, and would fail on the first real volume.

Someone else hit this too: libyal/libfsapfs issue #6, "Unable to open a test DMG
file created with APFS AES256".

Native encryption comes from `diskutil apfs encryptVolume` — what Finder's
"Encrypt" does.

### Mint recipe (reproducible on any Mac)

```bash
# 1. an UNENCRYPTED APFS volume in a sparse image
hdiutil create -size 128m -fs APFS -volname FVTEST -type SPARSE -o fv
dev=$(hdiutil attach -nobrowse fv.sparseimage | awk '/Apple_APFS/{print $1; exit}')
# note the synthesized volume node, e.g. disk10s1, from: diskutil list

# 2. a known plaintext marker, written BEFORE encryption
printf 'APFS-FILEVAULT-GROUND-TRUTH-MARKER-0123456789\n' > /Volumes/FVTEST/marker.txt
sync

# 3. APFS-NATIVE encryption
diskutil apfs encryptVolume disk10s1 -user disk -passphrase 'apfs-FV-TEST-2026'
# wait for: diskutil apfs list  =>  FileVault: Yes

# 4. image the container
diskutil unmount /Volumes/FVTEST
dd if=/dev/rdisk9s1 of=apfs-native-filevault.raw bs=1m
gzip -9 apfs-native-filevault.raw
```

### Verifying it is what it claims

The decisive check is the **marker**, not entropy:

```bash
gunzip -c apfs-native-filevault.raw.gz | strings | grep GROUND-TRUTH   # must find NOTHING
```

If the marker appears in the raw image, the file data was never encrypted and
the fixture is the wrong kind.

`APSB` **does** still appear in this image, and that is expected rather than a
defect: the volume was created unencrypted and then converted, so stale
checkpoint blocks retain plaintext volume superblocks. Requiring `APSB == 0`
would wrongly reject a valid fixture — the same residue a real
converted-in-place volume carries.

Container metadata (`NXSB`) is plaintext by design; APFS encrypts volume
contents, not the container superblock.

### Structure to expect

The container superblock's `nx_keylocker` points at the container keybag —
in this image, one block at paddr 356, high-entropy because APFS stores the
keybag encrypted (keyed from the container UUID). That is the entry point for
the unwrap chain: container keybag → volume keybag → KEK → VEK → AES-XTS.

## `dfvfs-apfs-encrypted.dmg.gz` — the Tier-1 corpus

The fixture above is **structurally incapable of exceeding Tier 2**: we minted
the volume, wrote the marker, and chose the password, so its ground truth is our
own. Confirming it confirms us. This one removes our authorship from every input.

| | |
|---|---|
| Source | [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) `test_data/apfs_encrypted.dmg` |
| Download | `https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/apfs_encrypted.dmg` |
| Password | `apfs-TEST` — dfVFS `tests/lib/apfs_helper.py`, `_APFS_PASSWORD` |
| Original MD5 | `8da806a7b49499eff6c4b32f3a75336e` |
| Original SHA-256 | `33fe6f183aeb1a95fec68efdab17d59aedbad3d8ef1a117d411117376d9d8485` |
| Original size | 4,194,304 bytes (GPT image; APFS container at byte **20480**) |
| Stored here | gzipped, 71,234 bytes, SHA-256 `efc62392c6f88201dedd0ff06e9787f6619a1913e38af0180dd63964581fe821` |
| Redistribution | Apache-2.0 (dfVFS), attribution above |
| Tier | **1** — third party authored the artifact, the password, and the answer key |

### The answer key, and where each part comes from

Nothing below was written by us:

| Expectation | Third-party source |
|---|---|
| root holds `.fseventsd`, `a_directory`, `a_link`, `passwords.txt` | `tests/vfs/apfs_file_entry.py`, `expected_sub_file_entry_names` |
| `/a_directory/another_file` inode = **21** | `APFSFileEntryTestEncrypted._IDENTIFIER_ANOTHER_FILE` |
| its bytes = `This is another file.\n` | `utils/generate_test_data_macos.sh` heredoc; matches committed `test_data/another_file`, SHA-256 `c7fbc0e821c0871805a99584c6a384533909f68a6bbe9a2a687d28d9f3b10c16` |
| `passwords.txt` begins `place,user,password` | the same generator heredoc |

### Two traps this fixture set, both hit

**Read the identifiers from the ENCRYPTED test class.** `apfs_file_entry.py`
declares `_IDENTIFIER_*` twice: once at the top for the unencrypted `apfs.raw`
(`another_file` = 19) and again inside `APFSFileEntryTestEncrypted` (= **21**).
Transcribing the first set produced a red test that looked exactly like a
decoder bug. Our reader was right and the note was wrong.

**Assert the BYTES, not the size.** An early version pinned only
`data.len() == 22`. Decryption cannot change how many bytes a file has, so that
assertion tests the extent map and nothing about the crypto — a deliberately
corrupted extent tweak passed it. It fails on the byte-exact assertion.

### Reproducing

```bash
curl -L -o apfs_encrypted.dmg \
  https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/apfs_encrypted.dmg
shasum -a 256 apfs_encrypted.dmg   # 33fe6f18...
gzip -9 -c apfs_encrypted.dmg > dfvfs-apfs-encrypted.dmg.gz
```

The container does not start at offset 0: it is partition 1 of a GPT disk,
beginning at byte 20480. The test slices there.


### The two dfVFS images are NOT built alike

Assuming parity between `apfs.raw` and `apfs_encrypted.dmg` cost a red. Measured
contents of the encrypted one:

```text
/              .fseventsd(16)  a_directory(18)  passwords.txt(19)  a_link(22)
/a_directory   a_file(20)  another_file(21)
xattrs         none on either file
a_link ->      a_directory/a_file
```

Against the plaintext image, which has `a_resourcefork`, a `myxattr` extended
attribute, and an `a_link` pointing at `another_file` instead. Different inode
numbers throughout.

So extended attributes and resource forks are Tier 1 on the **plaintext** corpus
only (`core/tests/dfvfs_tier1.rs`) — the encrypted image does not contain them,
and asserting them here would be asserting against a corpus that has nothing to
say. Symlink targets ARE validated through decryption, which matters because
APFS stores them in an embedded `com.apple.fs.symlink` xattr, so that path is
exercised on ciphertext.

`the_encrypted_corpus_carries_no_xattrs_or_resource_fork` pins this. It guards
the corpus, not the code: if dfVFS ever ships an encrypted image carrying them,
it fails and says to come and claim those paths here too.
