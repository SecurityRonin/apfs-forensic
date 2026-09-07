# dfVFS corpus — third-party images with third-party answer keys

Everything else in `tests/data/` is self-minted, which caps it at **Tier 2** by
construction: an image we made, holding content we wrote, checked against
expectations we chose. The decoder and the answer key share an author, so they
share his mistakes. These images remove our authorship from all three.

## `apfs.raw.gz` — unencrypted APFS

| | |
|---|---|
| Source | [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) `test_data/apfs.raw` |
| Download | `https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/apfs.raw` |
| Original SHA-256 | `e3e3adcbbf189403d892b013d6cba155f2e58e42ff5eb541ec681c37a91a3f29` |
| Original size | 4,153,344 bytes — a bare APFS container, **no partition table** |
| Stored here | gzipped, 8,520 bytes, SHA-256 `4634e22ef9d6828552c85b3f1f9e7e8bdd2c6e8a768b0a84de94eeb4dc9ce171` |
| Redistribution | Apache-2.0 (dfVFS), attribution above |
| Tier | **1** — third party authored the artifact and the answer key |
| Consumed by | `core/tests/dfvfs_tier1.rs` |

### The answer key

| Expectation | Third-party source |
|---|---|
| root = `.fseventsd`, `a_directory`, `a_link`, `passwords.txt` | `tests/vfs/apfs_file_entry.py`, `expected_sub_file_entry_names` |
| `a_directory` has 3 children | same, `number_of_sub_file_entries` |
| inodes: `a_directory` 16, `a_file` 17, `another_file` 19, `a_link` 20 | `APFSFileEntryTest._IDENTIFIER_*` |
| `another_file` = `This is another file.\n` | `utils/generate_test_data_macos.sh` heredoc |
| `a_file` = `This is a text file.\n\nWe should be able to parse it.\n` | same heredoc |
| xattr `myxattr` = `My extended attribute` | `xattr -w` in the generator; dfVFS asserts both name and value |
| `a_link` → `a_directory/another_file` | `ln -s` in the generator |
| `a_resourcefork` fork = `My resource fork\n` | `echo ... > .../..namedfork/rsrc` (echo supplies the newline) |

### Read the identifiers from the RIGHT class

`apfs_file_entry.py` declares `_IDENTIFIER_*` **twice** — at the top for
`apfs.raw`, and again inside `APFSFileEntryTestEncrypted` for
`apfs_encrypted.dmg`, with different values (`another_file` is 19 there, 21
here). Taking the wrong set produces a red that looks exactly like a decoder
bug. That happened once already while writing the encrypted suite, and the
reader was right both times.

### What this raised from Tier 2

Directory listing, path resolution, inode numbers, file byte assembly, extended
attributes, symlink targets and resource forks were all previously validated
only against fixtures we minted. `docs/validation.md` records the change.

### Controls

The tests pass on first run because they validate existing behaviour — no RED,
and fabricating one would be dishonest. They were instead shown capable of
failing by mutation: corrupting extent assembly, truncating an xattr value, and
dropping a directory entry each turn them red.

### Reproducing

```bash
curl -L -o apfs.raw \
  https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data/apfs.raw
shasum -a 256 apfs.raw   # e3e3adcb...
gzip -9 -c apfs.raw > apfs.raw.gz
```
