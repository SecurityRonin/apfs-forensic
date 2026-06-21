//! Fuzz target: B-tree node header + entry split. Invariant: must not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = apfs_core::btree::parse_node_header(data);
    let _ = apfs_core::btree::node_entries(data);
});
