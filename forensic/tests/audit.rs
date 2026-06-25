//! End-to-end analyzer drivers on the real self-minted container
//! `apfs_container_chain.bin` (Tier 2): a clean, freshly-minted image should
//! produce no integrity-breaking (High) anomalies.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use forensicnomicon::report::Observation;

const CHAIN: &[u8] = include_bytes!("../../tests/data/apfs_container_chain.bin");
const BLOCK_SIZE: usize = 4096;

#[test]
fn audit_container_on_clean_fixture_has_no_high_anomalies() {
    let mut r = Cursor::new(CHAIN);
    let findings = apfs_forensic::audit_container(&mut r, BLOCK_SIZE).expect("audit container");
    let high: Vec<&'static str> = findings
        .iter()
        .filter(|f| f.severity() == Some(apfs_forensic::Severity::High))
        .map(Observation::code)
        .collect();
    assert!(
        high.is_empty(),
        "a clean minted container must have no High anomalies, got {high:?}"
    );
}
