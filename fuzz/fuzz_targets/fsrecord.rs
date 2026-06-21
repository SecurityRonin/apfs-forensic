//! Fuzz target: j_key decode + xfield walk. Invariant: must not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 8 {
        let k = u64::from_le_bytes([data[0],data[1],data[2],data[3],data[4],data[5],data[6],data[7]]);
        let _ = apfs_core::fsrecord::decode_jkey(k);
    }
    let _ = apfs_core::fsrecord::parse_xfields(data);
});
