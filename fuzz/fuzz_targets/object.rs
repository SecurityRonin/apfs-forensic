//! Fuzz target: object header parse + Fletcher-64. Invariant: must not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = apfs_core::object::ObjPhys::parse(data);
    let _ = apfs_core::object::fletcher64_checksum(data);
});
