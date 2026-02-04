use core::array::ArrayTrait;
use core::poseidon::poseidon_hash_span;
use core::serde::Serde;

#[derive(Drop)]
pub struct MoneroEventV1 {
    pub chain_id: felt252,
    pub swap_id: felt252,
    pub txid: core::integer::u256,
    pub output_index: u32,
    pub amount_atomic: u64,
    pub recipient_view_tag: u8,
    pub lock_height: u64,
    pub confirmations: u32,
    pub timestamp: u64,
    pub deadline: u64,
}

const MONERO_EVENT_V1_DOMAIN: felt252 = 'MONERO_EVENT_V1';

pub fn compute_event_hash(event: @MoneroEventV1) -> felt252 {
    let mut elements: Array<felt252> = array![];
    let chain_id = *event.chain_id;
    let swap_id = *event.swap_id;
    let txid = *event.txid;
    let output_index = *event.output_index;
    let amount_atomic = *event.amount_atomic;
    let recipient_view_tag = *event.recipient_view_tag;
    let lock_height = *event.lock_height;
    let confirmations = *event.confirmations;
    let timestamp = *event.timestamp;
    let deadline = *event.deadline;

    elements.append(MONERO_EVENT_V1_DOMAIN);
    elements.append(chain_id);
    elements.append(swap_id);

    Serde::serialize(@txid.low, ref elements);
    Serde::serialize(@txid.high, ref elements);

    Serde::serialize(@output_index, ref elements);
    Serde::serialize(@amount_atomic, ref elements);
    Serde::serialize(@recipient_view_tag, ref elements);
    Serde::serialize(@lock_height, ref elements);
    Serde::serialize(@confirmations, ref elements);
    Serde::serialize(@timestamp, ref elements);
    Serde::serialize(@deadline, ref elements);

    poseidon_hash_span(elements.span())
}
