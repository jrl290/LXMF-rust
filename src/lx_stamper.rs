use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hkdf::Hkdf;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rand::RngCore;
use rmp::encode::write_uint;
use sha2::Sha256;

use reticulum_rust::identity::{self, HASHLENGTH};
use reticulum_rust::{host_os, log, LOG_DEBUG, LOG_ERROR, LOG_WARNING};

use crate::lx_message::LXMessage;

pub const WORKBLOCK_EXPAND_ROUNDS: usize = 3000;
pub const WORKBLOCK_EXPAND_ROUNDS_PN: usize = 1000;
pub const WORKBLOCK_EXPAND_ROUNDS_PEERING: usize = 25;
pub const STAMP_SIZE: usize = HASHLENGTH / 8;
pub const PN_VALIDATION_POOL_MIN_SIZE: usize = 256;

static ACTIVE_JOBS: Lazy<Mutex<HashMap<Vec<u8>, Arc<AtomicBool>>>> =
	Lazy::new(|| Mutex::new(HashMap::new()));

pub fn stamp_workblock(material: &[u8], expand_rounds: usize) -> Vec<u8> {
	let mut workblock = Vec::with_capacity(expand_rounds * 256);

	for n in 0..expand_rounds as u64 {
		let mut packed_n = Vec::new();
		let _ = write_uint(&mut packed_n, n);
		let mut salt_input = Vec::with_capacity(material.len() + packed_n.len());
		salt_input.extend_from_slice(material);
		salt_input.extend_from_slice(&packed_n);
		let salt = identity::full_hash(&salt_input);

		let hkdf = Hkdf::<Sha256>::new(Some(&salt), material);
		let mut derived = vec![0u8; 256];
		if hkdf.expand(&[], &mut derived).is_err() {
			log("HKDF expansion failed while generating stamp workblock", LOG_ERROR, false, false);
			break;
		}
		workblock.extend_from_slice(&derived);
	}

	workblock
}

pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u32 {
	let mut material = Vec::with_capacity(workblock.len() + stamp.len());
	material.extend_from_slice(workblock);
	material.extend_from_slice(stamp);
	let hash = identity::full_hash(&material);

	let mut value = 0u32;
	for byte in hash {
		if byte == 0 {
			value += 8;
		} else {
			value += byte.leading_zeros();
			break;
		}
	}

	value
}

pub fn stamp_valid(stamp: &[u8], target_cost: u32, workblock: &[u8]) -> bool {
	stamp_value(workblock, stamp) >= target_cost
}

pub fn validate_peering_key(peering_id: &[u8], peering_key: &[u8], target_cost: u32) -> bool {
	let workblock = stamp_workblock(peering_id, WORKBLOCK_EXPAND_ROUNDS_PEERING);
	stamp_valid(peering_key, target_cost, &workblock)
}

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

pub fn generate_stamp(message_id: &[u8], stamp_cost: u32, expand_rounds: usize) -> (Option<Vec<u8>>, u32) {
	log(
		format!("Generating stamp with cost {}", stamp_cost),
		LOG_DEBUG,
		false,
		false,
	);
	let workblock = stamp_workblock(message_id, expand_rounds);

	let start = Instant::now();
	let (stamp, rounds) = match host_os().as_str() {
		"windows" | "darwin" => job_simple(stamp_cost, &workblock, message_id),
		"android" => job_android(stamp_cost, &workblock, message_id),
		_ => job_linux(stamp_cost, &workblock, message_id),
	};

	let duration = start.elapsed().as_secs_f64();
	let speed = if duration > 0.0 { rounds as f64 / duration } else { 0.0 };
	let value = stamp
		.as_ref()
		.map(|s| stamp_value(&workblock, s))
		.unwrap_or(0);

	log(
		format!(
			"Stamp with value {} generated in {:.2}s, {} rounds, {} rounds per second",
			value,
			duration,
			rounds,
			speed as u64
		),
		LOG_DEBUG,
		false,
		false,
	);

	(stamp, value)
}

pub fn cancel_work(message_id: &[u8]) {
	let jobs = ACTIVE_JOBS.lock().unwrap();
	if let Some(stop_flag) = jobs.get(message_id) {
		stop_flag.store(true, Ordering::SeqCst);
	}
}

fn job_simple(stamp_cost: u32, workblock: &[u8], message_id: &[u8]) -> (Option<Vec<u8>>, u64) {
	let platform = host_os();
	log(
		format!(
			"Running stamp generation on {}, work limited to single CPU core", platform
		),
		LOG_WARNING,
		false,
		false,
	);

	let rounds_start = Instant::now();
	let mut rounds = 0u64;
	let mut stamp = vec![0u8; STAMP_SIZE];

	let stop_flag = Arc::new(AtomicBool::new(false));
	ACTIVE_JOBS
		.lock()
		.unwrap()
		.insert(message_id.to_vec(), Arc::clone(&stop_flag));

	loop {
		OsRng.fill_bytes(&mut stamp);
		rounds += 1;

		if stamp_valid(&stamp, stamp_cost, workblock) {
			break;
		}

		if stop_flag.load(Ordering::SeqCst) {
			ACTIVE_JOBS.lock().unwrap().remove(message_id);
			return (None, rounds);
		}

		if rounds % 2500 == 0 {
			let elapsed = rounds_start.elapsed().as_secs_f64();
			let speed = if elapsed > 0.0 { rounds as f64 / elapsed } else { 0.0 };
			log(
				format!(
					"Stamp generation running. {} rounds completed so far, {} rounds per second",
					rounds,
					speed as u64
				),
				LOG_DEBUG,
				false,
				false,
			);
		}
	}

	ACTIVE_JOBS.lock().unwrap().remove(message_id);
	(Some(stamp), rounds)
}

fn job_linux(stamp_cost: u32, workblock: &[u8], message_id: &[u8]) -> (Option<Vec<u8>>, u64) {
	let cores = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
	let jobs = if cores <= 12 { cores } else { cores / 2 };
	let stop_flag = Arc::new(AtomicBool::new(false));
	let (tx, rx) = mpsc::channel();
	let rounds_total = Arc::new(Mutex::new(0u64));

	ACTIVE_JOBS
		.lock()
		.unwrap()
		.insert(message_id.to_vec(), Arc::clone(&stop_flag));

	log(
		format!("Starting {} stamp generation workers", jobs),
		LOG_DEBUG,
		false,
		false,
	);

	for _ in 0..jobs {
		let stop = Arc::clone(&stop_flag);
		let sender = tx.clone();
		let wb = workblock.to_vec();
		let rounds_acc = Arc::clone(&rounds_total);
		thread::spawn(move || {
			let mut local_rounds = 0u64;
			let mut stamp = vec![0u8; STAMP_SIZE];
			while !stop.load(Ordering::SeqCst) {
				OsRng.fill_bytes(&mut stamp);
				local_rounds += 1;
				if stamp_valid(&stamp, stamp_cost, &wb) {
					stop.store(true, Ordering::SeqCst);
					let _ = sender.send(stamp.clone());
					break;
				}
			}
			if let Ok(mut total) = rounds_acc.lock() {
				*total += local_rounds;
			}
		});
	}

	let stamp = rx.recv_timeout(Duration::from_secs(30)).ok();
	stop_flag.store(true, Ordering::SeqCst);
	ACTIVE_JOBS.lock().unwrap().remove(message_id);

	let total_rounds = rounds_total.lock().unwrap_or_else(|e| e.into_inner());
	(stamp, *total_rounds)
}

fn job_android(stamp_cost: u32, workblock: &[u8], message_id: &[u8]) -> (Option<Vec<u8>>, u64) {
	job_simple(stamp_cost, workblock, message_id)
}
