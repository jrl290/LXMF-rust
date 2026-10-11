//! A payload Python LXMF refuses whole for its msgpack, judged as Python LXMF
//! judges it (RFed SPEC §17.14 "Repeated keys", James's ruling of 2026-10-11:
//! parity; "Unhashable keys" and "Nesting", decided 2026-10-11).
//!
//! LXMF 1.1.1 reads a message with RNS's vendored umsgpack, and
//! `LXMessage.unpack_from_bytes` lets any of its errors through, so
//! `LXMRouter.lxmf_delivery` drops the message whole. Three of them are about
//! a payload's shape, in any map or array at any depth:
//! - a map that repeats a key (`DuplicateKeyException`);
//! - a map whose key is a map, or an array that holds a map at any depth
//!   (`UnhashableKeyException`: umsgpack turns an array key into a tuple,
//!   which Python cannot hash when it holds a dict);
//! - a payload nested deeper than umsgpack's recursion reaches on the
//!   delivery path (`RecursionError`): [`NESTING_MAX_DEPTH`].
//!
//! Here [`refuse_as_python`] (through [`read_refusing`]) does the same for
//! every LXMF payload this crate reads: `LXMessage::unpack_from_bytes` (the
//! direct path, the propagation node's deliveries, paper messages, the
//! phones' group receipts), `channel::unpack` (a channel post, before its
//! sender's key is remembered), `LXMessage::unpack_from_file` (a stored
//! container, as LXMF.py reads it) and `distro::unwrap_blob` (the distro
//! path). No reader of the group entries, the group sync or a channel
//! membership message ever sees such a payload. The reason given is the first
//! that umsgpack meets reading the bytes in order: a key is read whole before
//! it is judged, a map key is refused before its value is read, and an array
//! key's value is read before the key is hashed.
//!
//! "Already in the dict" is Python's equality, so two keys of one map are one
//! key when:
//! - they are integers, floats or booleans of one numeric value, whatever the
//!   encoding: `1`, `0xcc 0x01`, `1.0` and `true` are one key, `0` and `-0.0`
//!   too; NaN is no key's equal, not even NaN's;
//! - they are str of the same code points (no normalisation), or bin of the
//!   same bytes; a str is never a bin;
//! - both are nil;
//! - they are ext of the same type and data, a timestamp (ext -1) by its
//!   instant to the microsecond, as Python's `datetime` compares it.
//!
//! An array key is never compared: umsgpack turns it into a tuple and skips
//! the check (and refuses it only when it holds a map). The `key_equality`,
//! `refused` and `nesting` vectors of tests/distro_group_sync_vectors.json,
//! each checked against the reference, pin every case.

use std::collections::HashSet;
use std::fmt;

use rmpv::Value;
use reticulum_rust::{log, LOG_NOTICE};

/// The start of every refusal's error text, so a caller that logs its own
/// errors can tell this one (already logged once, here) from the others.
pub const REFUSED_WHOLE: &str = "refused whole:";

/// RFed SPEC §17.14 "Nesting" (decided 2026-10-11: one limit, Python's
/// measured delivery-path depth): no value of a payload may be deeper than
/// this, the payload itself at depth 0, its fields map at 1, a field's value
/// at 2, and anything in an array or a map (a key too) one deeper than it. So
/// a field holds at most 492 nested arrays or maps whose innermost is empty
/// ([`NESTING_MAX_IN_A_FIELD`]), or 491 whose innermost holds anything. That
/// is where Python LXMF 1.1.1 (RNS 1.5.2's umsgpack, CPython 3.13, recursion
/// limit 1000) refuses a propagated message on its real delivery path
/// (`message_get_response` -> `lxmf_propagation` -> `lxmf_delivery`),
/// measured end to end by tests/delivery_nesting_probe.py; a direct delivery
/// over a link reads up to two levels more there. One limit for every client.
pub const NESTING_MAX_DEPTH: usize = 493;

/// [`NESTING_MAX_DEPTH`] counted in one field: the arrays or maps a field may
/// nest, the innermost empty.
pub const NESTING_MAX_IN_A_FIELD: usize = NESTING_MAX_DEPTH - 1;

/// Why Python LXMF refuses a payload whole. A depth is a map's or a value's
/// own (the payload itself is depth 0, the fields map depth 1, the Retichat
/// field's map depth 2).
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
	/// A map at `depth` repeats `key` (umsgpack `DuplicateKeyException`).
	RepeatedKey { depth: usize, key: Value },
	/// A map at `depth` has `key`, a map or an array that holds one (umsgpack
	/// `UnhashableKeyException`).
	UnhashableKey { depth: usize, key: Value },
	/// A value at `depth`, past [`NESTING_MAX_DEPTH`] (`RecursionError` on
	/// Python's delivery path). `None` when the decoder stopped first, at its
	/// own limit (rmpv reads about 510 levels).
	TooDeep { depth: Option<usize> },
}

/// `key` as text for a log line, cut to 64 bytes.
fn key_text(key: &Value) -> String {
	let mut key = key.to_string();
	if key.len() > 64 {
		let mut cut = 61;
		while !key.is_char_boundary(cut) {
			cut -= 1;
		}
		key.truncate(cut);
		key.push_str("...");
	}
	key
}

impl fmt::Display for Refusal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Refusal::RepeatedKey { depth, key } => write!(f, "a map at depth {depth} repeats a key ({})", key_text(key)),
			Refusal::UnhashableKey { depth, key } => {
				write!(f, "a map at depth {depth} has a key Python cannot hash ({})", key_text(key))
			}
			Refusal::TooDeep { depth: Some(depth) } => {
				write!(f, "a value at depth {depth} is nested past depth {NESTING_MAX_DEPTH}")
			}
			Refusal::TooDeep { depth: None } => {
				write!(f, "a value is nested past depth {NESTING_MAX_DEPTH} (past what the decoder reads)")
			}
		}
	}
}

impl Refusal {
	/// The reference's exception, and the rule of RFed SPEC §17.14 that
	/// follows it.
	fn source(&self) -> &'static str {
		match self {
			Refusal::RepeatedKey { .. } => "umsgpack DuplicateKeyException; RFed SPEC §17.14 \"Repeated keys\"",
			Refusal::UnhashableKey { .. } => "umsgpack UnhashableKeyException; RFed SPEC §17.14 \"Unhashable keys\"",
			Refusal::TooDeep { .. } => "RecursionError on its delivery path; RFed SPEC §17.14 \"Nesting\"",
		}
	}
}

/// A key as Python compares it.
#[derive(Hash, PartialEq, Eq)]
enum Key<'a> {
	Nil,
	/// An integer, a boolean, or a float with no fraction, by its exact value.
	Number(i128),
	/// Any other float but NaN (a fraction, an infinity, or beyond any
	/// integer msgpack holds), by its bits as f64.
	Float(u64),
	Str(&'a [u8]),
	Bin(&'a [u8]),
	/// A timestamp ext, by microseconds since the epoch.
	Instant(i128),
	Ext(i8, &'a [u8]),
}

fn float_key(f: f64) -> Option<Key<'static>> {
	if f.is_nan() {
		return None;
	}
	// 2^127: past it no integer key could be equal (msgpack's are 64-bit), and
	// the cast below would saturate.
	if f.is_finite() && f.fract() == 0.0 && f.abs() < 1.7014118346046923e38 {
		Some(Key::Number(f as i128))
	} else {
		Some(Key::Float(f.to_bits()))
	}
}

/// The instant of a timestamp ext's data, in microseconds since the epoch, as
/// umsgpack's `_unpack_ext_timestamp` makes it (nanoseconds floored to
/// microseconds). `None` for a length it refuses (another refusal than this).
fn timestamp_micros(data: &[u8]) -> Option<i128> {
	let (seconds, nanoseconds) = match data.len() {
		4 => (i128::from(u32::from_be_bytes(data.try_into().ok()?)), 0),
		8 => {
			let value = u64::from_be_bytes(data.try_into().ok()?);
			(i128::from(value & 0x3_ffff_ffff), i128::from(value >> 34))
		}
		12 => (
			i128::from(i64::from_be_bytes(data[4..12].try_into().ok()?)),
			i128::from(u32::from_be_bytes(data[..4].try_into().ok()?)),
		),
		_ => return None,
	};
	Some(seconds * 1_000_000 + nanoseconds / 1000)
}

/// `key` as Python compares it, or `None` when Python never finds it in the
/// dict (NaN; an array; a map, which [`walk`] refuses first).
fn key_of(key: &Value) -> Option<Key<'_>> {
	Some(match key {
		Value::Nil => Key::Nil,
		Value::Boolean(b) => Key::Number(i128::from(*b)),
		Value::Integer(n) => Key::Number(n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from))?),
		Value::F32(f) => float_key(f64::from(*f))?,
		Value::F64(f) => float_key(*f)?,
		Value::String(s) => Key::Str(s.as_bytes()),
		Value::Binary(b) => Key::Bin(b),
		Value::Ext(-1, data) => timestamp_micros(data).map_or(Key::Ext(-1, data), Key::Instant),
		Value::Ext(t, data) => Key::Ext(*t, data),
		Value::Array(_) | Value::Map(_) => return None,
	})
}

/// Whether the array `key` holds a map at any depth (Python cannot hash the
/// tuple umsgpack makes of it then).
fn holds_map(key: &[Value]) -> bool {
	key.iter().any(|item| match item {
		Value::Map(_) => true,
		Value::Array(items) => holds_map(items),
		_ => false,
	})
}

/// The first reason Python LXMF refuses `value` (a payload, at depth 0)
/// whole, in the order umsgpack reads its bytes, or `None` when it reads it.
pub fn refusal(value: &Value) -> Option<Refusal> {
	walk(value, 0)
}

/// [`refusal`] of `value` at `depth`. It recurses once a level, never past
/// [`NESTING_MAX_DEPTH`] + 1, which the decoder before it has recursed too.
fn walk(value: &Value, depth: usize) -> Option<Refusal> {
	if depth > NESTING_MAX_DEPTH {
		return Some(Refusal::TooDeep { depth: Some(depth) });
	}
	match value {
		Value::Array(items) => items.iter().find_map(|item| walk(item, depth + 1)),
		Value::Map(entries) => {
			let mut seen = HashSet::with_capacity(entries.len());
			for (key, item) in entries {
				// umsgpack reads the key whole first.
				if let Some(refused) = walk(key, depth + 1) {
					return Some(refused);
				}
				match key {
					// A map is no key: refused before its value is read.
					Value::Map(_) => return Some(Refusal::UnhashableKey { depth, key: key.clone() }),
					// An array key is never compared; its value is read, then
					// the key is hashed, which fails when it holds a map.
					Value::Array(items) => {
						if let Some(refused) = walk(item, depth + 1) {
							return Some(refused);
						}
						if holds_map(items) {
							return Some(Refusal::UnhashableKey { depth, key: key.clone() });
						}
						continue;
					}
					_ => {
						if let Some(k) = key_of(key) {
							if !seen.insert(k) {
								return Some(Refusal::RepeatedKey { depth, key: key.clone() });
							}
						}
					}
				}
				if let Some(refused) = walk(item, depth + 1) {
					return Some(refused);
				}
			}
			None
		}
		_ => None,
	}
}

/// `Err` when Python LXMF refuses `payload` whole ([`refusal`]): the message
/// is refused whole, and this logs the one line that says so. `what` names
/// the message for that line (e.g. "LXMF message from <source>"). The error
/// text starts with [`REFUSED_WHOLE`] and says why ("repeats a key", "cannot
/// hash", "nested past depth").
pub fn refuse_as_python(payload: &Value, what: &str) -> Result<(), String> {
	match refusal(payload) {
		None => Ok(()),
		Some(refused) => Err(refuse(&refused, what)),
	}
}

/// Logs the one line of `refused` and returns its error text.
fn refuse(refused: &Refusal, what: &str) -> String {
	let why = format!("{REFUSED_WHOLE} {refused}, as Python LXMF refuses it ({})", refused.source());
	log(&format!("[LXMF] {what} {why}"), LOG_NOTICE, false, false);
	why
}

/// Reads one msgpack value from the front of `bytes` and refuses it whole as
/// [`refuse_as_python`] does, logging that once; a value nested past the
/// decoder's own limit is refused the same way ([`Refusal::TooDeep`]). Any
/// other decode error is `decode_error`'s text, not logged here.
pub fn read_refusing(
	bytes: &[u8],
	what: &str,
	decode_error: impl FnOnce(rmpv::decode::Error) -> String,
) -> Result<Value, String> {
	let value = match rmpv::decode::read_value(&mut &bytes[..]) {
		Ok(value) => value,
		Err(rmpv::decode::Error::DepthLimitExceeded) => return Err(refuse(&Refusal::TooDeep { depth: None }, what)),
		Err(e) => return Err(decode_error(e)),
	};
	refuse_as_python(&value, what)?;
	Ok(value)
}

/// Whether `error` is a refusal [`refuse_as_python`] has logged already.
pub fn is_refusal(error: &str) -> bool {
	error.starts_with(REFUSED_WHOLE)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn map(keys: Vec<Value>) -> Value {
		Value::Map(keys.into_iter().enumerate().map(|(i, k)| (k, Value::from(i as u64))).collect())
	}

	fn repeats(keys: Vec<Value>) -> bool {
		matches!(refusal(&map(keys)), Some(Refusal::RepeatedKey { .. }))
	}

	/// `levels` arrays nested one in the next, the innermost empty.
	fn arrays(levels: usize) -> Value {
		(1..levels).fold(Value::Array(vec![]), |inner, _| Value::Array(vec![inner]))
	}

	/// A payload [timestamp, title, content, fields] whose fields map holds `field` under 0x77.
	fn payload(field: Value) -> Value {
		Value::Array(vec![
			Value::F64(1.0),
			Value::Binary(vec![]),
			Value::Binary(vec![]),
			Value::Map(vec![(Value::from(0x77u8), field)]),
		])
	}

	/// Runs `f` on a thread with a 64 MiB stack: a debug build spends about 4.9 KB of stack a
	/// level in rmpv's reader and its Value's drop (about 260 B in release).
	fn on_a_large_stack(f: fn()) {
		std::thread::Builder::new().stack_size(64 << 20).spawn(f).unwrap().join().unwrap();
	}

	#[test]
	fn numbers_are_one_key_by_value_whatever_their_type() {
		assert!(repeats(vec![Value::from(1u8), Value::from(1u64)]));
		assert!(repeats(vec![Value::from(-1i8), Value::from(-1i64)]));
		assert!(repeats(vec![Value::from(1u8), Value::F64(1.0)]));
		assert!(repeats(vec![Value::from(1u8), Value::F32(1.0)]));
		assert!(repeats(vec![Value::Boolean(true), Value::from(1u8)]));
		assert!(repeats(vec![Value::Boolean(false), Value::F64(-0.0)]));
		assert!(repeats(vec![Value::F32(1.5), Value::F64(1.5)]));
		assert!(repeats(vec![Value::F32(f32::INFINITY), Value::F64(f64::INFINITY)]));
		assert!(!repeats(vec![Value::F64(f64::NAN), Value::F64(f64::NAN)]), "NaN equals nothing");
		assert!(!repeats(vec![Value::from(u64::MAX), Value::F64(18446744073709551616.0)]), "2^64 - 1 is not 2^64");
		assert!(!repeats(vec![Value::from(1u8), Value::from(2u8)]));
		assert!(!repeats(vec![Value::F64(f64::INFINITY), Value::F64(f64::NEG_INFINITY)]));
	}

	#[test]
	fn str_bin_nil_and_ext_keys() {
		assert!(repeats(vec![Value::from("a"), Value::from("a")]));
		assert!(!repeats(vec![Value::from("a"), Value::Binary(b"a".to_vec())]), "a str is never a bin");
		assert!(repeats(vec![Value::Binary(b"a".to_vec()), Value::Binary(b"a".to_vec())]));
		assert!(!repeats(vec![Value::from(1u8), Value::from("1")]));
		assert!(!repeats(vec![Value::from("\u{e9}"), Value::from("e\u{301}")]), "never normalised");
		assert!(repeats(vec![Value::Nil, Value::Nil]));
		assert!(repeats(vec![Value::Ext(5, vec![0]), Value::Ext(5, vec![0])]));
		assert!(!repeats(vec![Value::Ext(5, vec![0]), Value::Ext(6, vec![0])]));
		// The epoch as timestamp 32 and as timestamp 64; one second and one second
		// and 999 ns (floored to microseconds) as timestamp 32 and 96.
		assert!(repeats(vec![Value::Ext(-1, vec![0; 4]), Value::Ext(-1, vec![0; 8])]));
		let mut ts96 = 999u32.to_be_bytes().to_vec();
		ts96.extend_from_slice(&1i64.to_be_bytes());
		assert!(repeats(vec![Value::Ext(-1, 1u32.to_be_bytes().to_vec()), Value::Ext(-1, ts96)]));
		let mut ts96 = 1000u32.to_be_bytes().to_vec();
		ts96.extend_from_slice(&1i64.to_be_bytes());
		assert!(!repeats(vec![Value::Ext(-1, 1u32.to_be_bytes().to_vec()), Value::Ext(-1, ts96)]));
	}

	#[test]
	fn an_array_key_is_never_compared() {
		let one = Value::Array(vec![Value::from(1u8)]);
		assert!(!repeats(vec![one.clone(), one]));
	}

	/// Any depth: in a map nested in a map, in an array, in a key; the depth is reported.
	#[test]
	fn a_repeat_is_found_at_any_depth() {
		let inner = map(vec![Value::from(0u8), Value::from(0u8)]);
		let fields = Value::Map(vec![(Value::from(0xD1u8), Value::Map(vec![(Value::from(10u8), inner.clone())]))]);
		let payload = Value::Array(vec![Value::F64(1.0), Value::Binary(vec![]), Value::Binary(vec![]), fields]);
		assert_eq!(refusal(&payload), Some(Refusal::RepeatedKey { depth: 3, key: Value::from(0u8) }));
		assert!(refusal(&Value::Array(vec![Value::Array(vec![inner.clone()])])).is_some());
		assert!(refusal(&Value::Map(vec![(Value::Array(vec![inner]), Value::Nil)])).is_some(), "inside a key");
		let distinct = map(vec![Value::from(0u8), Value::from(1u8)]);
		assert_eq!(refusal(&Value::Array(vec![distinct.clone(), distinct])), None, "two maps, each with its own keys");
	}

	#[test]
	fn the_refusal_names_itself() {
		let err = refuse_as_python(&map(vec![Value::from(0xA0u8), Value::from(0xA0u16)]), "a test message").unwrap_err();
		assert!(is_refusal(&err) && err.contains("repeats a key (160)") && err.contains("depth 0"), "{err}");
		assert!(err.contains("DuplicateKeyException"), "{err}");
		assert_eq!(refuse_as_python(&map(vec![Value::from(1u8)]), "a test message"), Ok(()));
		assert!(!is_refusal("msgpack decode error"));
		let long = Refusal::RepeatedKey { depth: 1, key: Value::from("é".repeat(100).as_str()) };
		assert!(long.to_string().len() < 120);
		let unhashable = refuse_as_python(&Value::Map(vec![(Value::Map(vec![]), Value::Nil)]), "a test message").unwrap_err();
		assert!(is_refusal(&unhashable) && unhashable.contains("depth 0 has a key Python cannot hash ({})"), "{unhashable}");
		assert!(unhashable.contains("UnhashableKeyException"), "{unhashable}");
		// 495 arrays: the outermost at depth 0, the innermost at 494.
		let deep = refuse_as_python(&arrays(NESTING_MAX_DEPTH + 2), "a test message").unwrap_err();
		assert!(is_refusal(&deep) && deep.contains("a value at depth 494 is nested past depth 493"), "{deep}");
		assert!(deep.contains("RecursionError"), "{deep}");
	}

	/// RFed SPEC §17.14 "Unhashable keys": a map key, or an array key that holds a map at any
	/// depth, at any depth of the payload; an array key that holds no map is read.
	#[test]
	fn a_map_key_or_an_array_key_holding_a_map_is_unhashable() {
		let empty_map = Value::Map(vec![]);
		let unhashable = |key: Value| {
			let fields = Value::Map(vec![(Value::from(0xA0u8), Value::from("id")), (key.clone(), Value::from(0u8))]);
			refusal(&fields) == Some(Refusal::UnhashableKey { depth: 0, key })
		};
		assert!(unhashable(empty_map.clone()));
		assert!(unhashable(map(vec![Value::from(1u8)])));
		assert!(unhashable(Value::Array(vec![empty_map.clone()])));
		assert!(unhashable(Value::Array(vec![Value::from(1u8), Value::Array(vec![Value::Array(vec![empty_map.clone()])])])));
		for read in [
			Value::Array(vec![]),
			Value::Array(vec![Value::Array(vec![Value::from(1u8)])]),
			Value::Array(vec![Value::Binary(b"a".to_vec()), Value::Ext(5, vec![0]), Value::F64(f64::NAN)]),
		] {
			assert_eq!(refusal(&Value::Map(vec![(read.clone(), Value::Nil)])), None, "{read}");
		}
		// At any depth: in 0xD1's key 10, and in a map in an array in a field.
		let retichat = Value::Map(vec![(
			Value::from(0xD1u8),
			Value::Map(vec![(Value::from(10u8), Value::Map(vec![(empty_map.clone(), Value::from(0u8))]))]),
		)]);
		assert_eq!(refusal(&retichat), Some(Refusal::UnhashableKey { depth: 2, key: empty_map.clone() }));
		let in_array = payload(Value::Array(vec![Value::Map(vec![(empty_map.clone(), Value::from(1u8))])]));
		assert_eq!(refusal(&in_array), Some(Refusal::UnhashableKey { depth: 3, key: empty_map }));
	}

	/// The first reason in the order umsgpack reads the bytes: a key is read whole before it is
	/// judged, a map key is refused before its value is read, an array key's value is read before
	/// the key is hashed (the `refused` vectors' reasons, checked against the reference).
	#[test]
	fn the_reason_is_the_first_umsgpack_meets() {
		let twice = map(vec![Value::from(0u8), Value::from(0u8)]);
		let empty_map = Value::Map(vec![]);
		let holding_map = Value::Array(vec![empty_map.clone()]);
		let first = |entries: Vec<(Value, Value)>| refusal(&Value::Map(entries));
		assert_eq!(first(vec![(twice.clone(), Value::Nil)]), Some(Refusal::RepeatedKey { depth: 1, key: Value::from(0u8) }));
		assert_eq!(
			first(vec![(empty_map.clone(), twice.clone())]),
			Some(Refusal::UnhashableKey { depth: 0, key: empty_map.clone() })
		);
		assert_eq!(
			first(vec![(holding_map.clone(), twice.clone())]),
			Some(Refusal::RepeatedKey { depth: 1, key: Value::from(0u8) })
		);
		assert_eq!(
			first(vec![(holding_map.clone(), Value::Nil), (Value::from(5u8), Value::Nil), (Value::from(5u8), Value::Nil)]),
			Some(Refusal::UnhashableKey { depth: 0, key: holding_map })
		);
		assert_eq!(
			first(vec![(Value::from(5u8), Value::Nil), (Value::from(5u8), twice), (empty_map.clone(), Value::Nil)]),
			Some(Refusal::RepeatedKey { depth: 0, key: Value::from(5u8) })
		);
	}

	/// RFed SPEC §17.14 "Nesting": a value at depth 493 is read, at 494 refused, whatever it is
	/// (an array, a map, a key, a scalar); 492 arrays nested in a field are the limit.
	#[test]
	fn nothing_is_read_past_depth_493() {
		on_a_large_stack(|| {
			assert_eq!(NESTING_MAX_IN_A_FIELD, 492);
			assert_eq!(refusal(&payload(arrays(NESTING_MAX_IN_A_FIELD))), None, "492 arrays in a field");
			assert_eq!(
				refusal(&payload(arrays(NESTING_MAX_IN_A_FIELD + 1))),
				Some(Refusal::TooDeep { depth: Some(494) }),
				"493 arrays in a field"
			);
			let holding = |levels: usize, leaf: Value| {
				(1..levels).fold(Value::Array(vec![leaf]), |inner, _| Value::Array(vec![inner]))
			};
			assert_eq!(refusal(&payload(holding(491, Value::from("a")))), None, "a str at depth 493");
			assert!(refusal(&payload(holding(492, Value::from(0u8)))).is_some(), "an int at depth 494");
			let maps = (1..NESTING_MAX_IN_A_FIELD).fold(Value::Map(vec![]), |inner, _| Value::Map(vec![(Value::from(0u8), inner)]));
			assert_eq!(refusal(&payload(maps.clone())), None, "492 maps in a field");
			assert!(refusal(&payload(Value::Map(vec![(Value::from(0u8), maps)]))).is_some(), "493 maps");
			let key = |levels| payload(Value::Map(vec![(arrays(levels), Value::from(0u8))]));
			assert_eq!(refusal(&key(491)), None, "a key nesting to depth 493");
			assert!(refusal(&key(492)).is_some(), "a key nesting to depth 494");
		});
	}

	/// read_refusing: the decoder's own depth error is the same refusal, logged the same way; any
	/// other decode error is the caller's text.
	#[test]
	fn read_refusing_refuses_what_the_decoder_cannot_read_for_its_depth() {
		on_a_large_stack(|| {
			let mut deep = vec![0x91u8; 600];
			deep.push(0x90);
			let err = read_refusing(&deep, "a test message", |e| format!("decode: {e}")).unwrap_err();
			assert!(is_refusal(&err) && err.contains("nested past depth 493 (past what the decoder reads)"), "{err}");
			// 494 arrays then an empty one: the innermost at depth 494, refused by the walk.
			let mut past = vec![0x91u8; NESTING_MAX_DEPTH + 1];
			past.push(0x90);
			let err = read_refusing(&past, "a test message", |e| format!("decode: {e}")).unwrap_err();
			assert!(is_refusal(&err) && err.contains("a value at depth 494"), "{err}");
			past.remove(0);
			assert!(read_refusing(&past, "a test message", |e| format!("decode: {e}")).is_ok(), "depth 493 is read");
			assert_eq!(read_refusing(&[0x92, 0x01], "a test message", |_| "not msgpack".into()), Err("not msgpack".into()));
		});
	}
}
