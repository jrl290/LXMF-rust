//! LXMF stamp handling.
//!
//! The proof-of-work algorithm itself lives in `reticulum_rust::lxstamper` and
//! is re-exported here unchanged. It used to be reimplemented in this file —
//! two copies of one algorithm that the wider Reticulum network also
//! implements, which is how the copy in reticulum_rust drifted out of parity
//! with LXMF's Python reference without anything failing loudly.
//!
//! What stays here is the part that is genuinely LXMF's: propagation-node stamp
//! validation, which has to know `LXMessage::LXMF_OVERHEAD` to split a transient
//! blob from its stamp.

use std::thread;

use reticulum_rust::identity;
use reticulum_rust::host_os;

pub use reticulum_rust::lxstamper::{
	cancel_work, generate_stamp, is_legacy_stamp, legacy_stamp_workblock, stamp_valid,
	stamp_value, stamp_workblock, validate_peering_key, LXStamper, STAMP_SIZE,
	WORKBLOCK_EXPAND_ROUNDS, WORKBLOCK_EXPAND_ROUNDS_PEERING, WORKBLOCK_EXPAND_ROUNDS_PN,
};

use crate::lx_message::LXMessage;

pub const PN_VALIDATION_POOL_MIN_SIZE: usize = 256;

pub fn validate_pn_stamp(transient_data: &[u8], target_cost: u32) -> Option<(Vec<u8>, Vec<u8>, u32, Vec<u8>)> {
	if transient_data.len() <= LXMessage::LXMF_OVERHEAD + STAMP_SIZE {
		return None;
	}

	let (lxm_data, stamp) = transient_data.split_at(transient_data.len() - STAMP_SIZE);
	let transient_id = identity::full_hash(lxm_data);
	let workblock = stamp_workblock(&transient_id, WORKBLOCK_EXPAND_ROUNDS_PN);

	if !stamp_valid(stamp, target_cost, &workblock) {
		return None;
	}

	let value = stamp_value(&workblock, stamp);
	Some((transient_id, lxm_data.to_vec(), value, stamp.to_vec()))
}

pub fn validate_pn_stamps_job_simple(
	transient_list: &[Vec<u8>],
	target_cost: u32,
) -> Vec<(Vec<u8>, Vec<u8>, u32, Vec<u8>)> {
	let mut validated = Vec::new();
	for transient in transient_list {
		if let Some(entry) = validate_pn_stamp(transient, target_cost) {
			validated.push(entry);
		}
	}

	validated
}

pub fn validate_pn_stamps_job_multip(
	transient_list: &[Vec<u8>],
	target_cost: u32,
) -> Vec<(Vec<u8>, Vec<u8>, u32, Vec<u8>)> {
	let workers = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
	let chunk_size = (transient_list.len() / workers).max(1);
	let mut handles = Vec::new();

	for chunk in transient_list.chunks(chunk_size) {
		let chunk_vec = chunk.to_vec();
		handles.push(thread::spawn(move || validate_pn_stamps_job_simple(&chunk_vec, target_cost)));
	}

	let mut validated = Vec::new();
	for handle in handles {
		if let Ok(entries) = handle.join() {
			validated.extend(entries);
		}
	}

	validated
}

pub fn validate_pn_stamps(
	transient_list: &[Vec<u8>],
	target_cost: u32,
) -> Vec<(Vec<u8>, Vec<u8>, u32, Vec<u8>)> {
	let non_mp_platform = host_os() == "android";
	if transient_list.len() <= PN_VALIDATION_POOL_MIN_SIZE || non_mp_platform {
		validate_pn_stamps_job_simple(transient_list, target_cost)
	} else {
		validate_pn_stamps_job_multip(transient_list, target_cost)
	}
}

