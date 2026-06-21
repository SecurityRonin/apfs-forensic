//! Transparent decmpfs decompression (REUSE — not reinvented).
//!
//! APFS reuses HFS+'s `com.apple.decmpfs` scheme verbatim: a 16-byte header
//! (`MAGIC 0x636d_7066` "fpmc", a compression-type byte, uncompressed size),
//! `CHUNK_SIZE 65536`, payload either embedded in the xattr or in the
//! `com.apple.ResourceFork` xattr / a data stream. The fleet already solved and
//! validated this against real macOS in `hfsplus-forensic`:
//!
//! - **type→algorithm/storage map**: [`forensicnomicon::decmpfs::classify`]
//!   (`MAGIC`, `Storage`, `Algorithm`, `Compression`, `CHUNK_SIZE`) — used here,
//!   not re-defined.
//! - **zlib/DEFLATE (types 3/4)**: `flate2`.
//! - **LZVN (types 7/8)**: the `lzvn` crate (length-tolerant — real decmpfs LZVN
//!   blocks carry trailing bytes after end-of-stream that `lzfse_rust`'s strict
//!   path rejects).
//! - **LZFSE (types 11/12)**: `lzfse_rust`.
//!
//! All pure-Rust, preserving `unsafe_code = "forbid"`. The only APFS-specific
//! part is locating the decmpfs payload (xattr vs resource-fork vs dstream).

/// Decompress a decmpfs payload given its header + (embedded or stream) data.
///
/// # Errors
/// Returns an error on an unrecognized compression type (carrying the raw type
/// byte) or a codec failure — never fabricates plaintext.
pub fn decompress_decmpfs(_header: &[u8], _payload: &[u8]) -> crate::Result<Vec<u8>> {
    todo!("P4: classify via forensicnomicon::decmpfs, dispatch to flate2/lzvn/lzfse_rust")
}
