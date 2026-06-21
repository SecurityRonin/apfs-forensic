//! Fuzz target: NXSB container superblock parse. Invariant: must not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = apfs_core::container::NxSuperblock::parse(data);
});
