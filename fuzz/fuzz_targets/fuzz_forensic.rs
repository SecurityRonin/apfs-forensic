//! Fuzz target: full open→navigate→audit pipeline over arbitrary bytes.
//! Invariant: must not panic (a malformed image yields a loud error, not a crash).
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if let Ok(container) = apfs_core::ApfsContainer::open(Cursor::new(data.to_vec())) {
        let _ = apfs_forensic::audit_container(&container);
    }
});
