//! Fuzz target: B-tree node header + entry split. Invariant: must not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = apfs_core::btree::parse_node_header(data);
    // Exercise both subtypes (fixed-KV omap vs variable-KV fstree); pick from the
    // input so the fuzzer covers each path.
    let subtype = if data.first().is_some_and(|b| b & 1 == 0) {
        apfs_core::btree::BTreeSubtype::Omap
    } else {
        apfs_core::btree::BTreeSubtype::FsTree
    };
    let _ = apfs_core::btree::node_entries(data, subtype);
});
