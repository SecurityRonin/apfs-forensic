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
