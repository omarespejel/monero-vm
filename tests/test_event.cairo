use monero_vm::attestation::event::{MoneroEventV1, compute_event_hash};
use core::integer::u256;

fn sample_event() -> MoneroEventV1 {
    MoneroEventV1 {
        chain_id: 'SN_SEPOLIA',
        swap_id: 0x1234,
        txid: u256 { low: 1_u128, high: 2_u128 },
        output_index: 0_u32,
        amount_atomic: 10_u64,
        recipient_view_tag: 0_u8,
        lock_height: 100_u64,
        confirmations: 12_u32,
        timestamp: 1_700_000_000_u64,
        deadline: 1_700_000_100_u64,
    }
}

#[test]
fn test_event_hash_deterministic() {
    let event = sample_event();
    let hash_1 = compute_event_hash(@event);
    let hash_2 = compute_event_hash(@event);
    assert_eq!(hash_1, hash_2);
}

#[test]
fn test_event_hash_changes_with_fields() {
    let event = sample_event();
    let mut event_changed = sample_event();
    event_changed.output_index = 1_u32;

    let hash_1 = compute_event_hash(@event);
    let hash_2 = compute_event_hash(@event_changed);
    assert!(hash_1 != hash_2);
}
