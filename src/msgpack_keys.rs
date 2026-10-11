//! A msgpack map that repeats a key, judged as Python LXMF judges it (RFed
//! SPEC §17.14 "Repeated keys"; James's ruling of 2026-10-11: parity).
//!
//! LXMF 1.1.1 reads a message with RNS's vendored umsgpack, whose map reader
//! raises `DuplicateKeyException` when a key is already in the dict it is
//! building, in any map at any depth. `LXMessage.unpack_from_bytes` lets it
//! through and `LXMRouter.lxmf_delivery` drops the message whole. Here
//! [`refuse_repeated_keys`] does the same for every LXMF payload this crate
//! reads: `LXMessage::unpack_from_bytes` (the direct path, the propagation
//! node's deliveries, paper messages, the phones' group receipts),
//! `channel::unpack` (a channel post, before its sender's key is remembered),
//! `LXMessage::unpack_from_file` (a stored container, as LXMF.py reads it) and
//! `distro::unwrap_blob` (the distro path). No reader of the group entries,
//! the group sync or a channel membership message ever sees such a map.
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
//! the check. The `key_equality` vectors of
//! tests/distro_group_sync_vectors.json, checked against the reference, pin
//! each case.
//!
//! Not covered, and not ruled (open for James since 2026-10-11): umsgpack
//! refuses two more payloads whole, for other reasons than a repeated key. A
//! map used as a key, or an array key that holds a map, raises
//! `UnhashableKeyException`; this walk skips both and rmpv reads them. A
//! payload nested past Python's recursion limit raises `RecursionError`: with
//! arrays nested in a field, from about 496 of them in a fresh interpreter
//! (fewer under LXMRouter's stack), while rmpv refuses only from 510.

use std::collections::HashSet;
use std::fmt;

use rmpv::Value;
use reticulum_rust::{log, LOG_NOTICE};

/// The start of every refusal's error text, so a caller that logs its own
/// errors can tell this one (already logged once, here) from the others.
pub const REFUSED_WHOLE: &str = "refused whole:";

/// Where a map repeats a key: its depth (the payload itself is depth 0, the
/// fields map depth 1, the Retichat field's map depth 2) and the key.
#[derive(Debug, Clone, PartialEq)]
pub struct RepeatedKey {
	pub depth: usize,
	pub key: Value,
}

impl fmt::Display for RepeatedKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut key = self.key.to_string();
		if key.len() > 64 {
			let mut cut = 61;
			while !key.is_char_boundary(cut) {
				cut -= 1;
			}
			key.truncate(cut);
			key.push_str("...");
		}
		write!(f, "a map at depth {} repeats a key ({key})", self.depth)
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
/// dict (NaN; an array; a map, which it refuses for another reason).
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

/// The first map in `value`, at any depth (keys included), that repeats a key
/// as Python's umsgpack judges it, or `None`.
pub fn repeated_key(value: &Value) -> Option<RepeatedKey> {
	let mut stack = vec![(value, 0usize)];
	while let Some((value, depth)) = stack.pop() {
		match value {
			Value::Array(items) => stack.extend(items.iter().rev().map(|item| (item, depth + 1))),
			Value::Map(entries) => {
				let mut seen = HashSet::with_capacity(entries.len());
				for (key, _) in entries {
					if let Some(k) = key_of(key) {
						if !seen.insert(k) {
							return Some(RepeatedKey { depth, key: key.clone() });
						}
					}
				}
				for (key, item) in entries.iter().rev() {
					stack.push((item, depth + 1));
					stack.push((key, depth + 1));
				}
			}
			_ => {}
		}
	}
	None
}

/// `Err` when `payload` holds a map that repeats a key: the message is refused
/// whole, and this logs the one line that says so. `what` names the message
/// for that line (e.g. "LXMF message from <source>"). The error text starts
/// with [`REFUSED_WHOLE`] and says "repeats a key".
pub fn refuse_repeated_keys(payload: &Value, what: &str) -> Result<(), String> {
	match repeated_key(payload) {
		None => Ok(()),
		Some(repeat) => {
			let why = format!(
				"{REFUSED_WHOLE} {repeat}, as Python LXMF refuses it (umsgpack DuplicateKeyException; RFed SPEC §17.14 \"Repeated keys\")"
			);
			log(&format!("[LXMF] {what} {why}"), LOG_NOTICE, false, false);
			Err(why)
		}
	}
}

/// Whether `error` is a refusal [`refuse_repeated_keys`] has logged already.
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
		repeated_key(&map(keys)).is_some()
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
		assert_eq!(repeated_key(&payload), Some(RepeatedKey { depth: 3, key: Value::from(0u8) }));
		assert!(repeated_key(&Value::Array(vec![Value::Array(vec![inner.clone()])])).is_some());
		assert!(repeated_key(&Value::Map(vec![(Value::Array(vec![inner]), Value::Nil)])).is_some(), "inside a key");
		let distinct = map(vec![Value::from(0u8), Value::from(1u8)]);
		assert_eq!(repeated_key(&Value::Array(vec![distinct.clone(), distinct])), None, "two maps, each with its own keys");
	}

	#[test]
	fn the_refusal_names_itself() {
		let err = refuse_repeated_keys(&map(vec![Value::from(0xA0u8), Value::from(0xA0u16)]), "a test message").unwrap_err();
		assert!(is_refusal(&err) && err.contains("repeats a key (160)") && err.contains("depth 0"), "{err}");
		assert_eq!(refuse_repeated_keys(&map(vec![Value::from(1u8)]), "a test message"), Ok(()));
		assert!(!is_refusal("msgpack decode error"));
		let long = RepeatedKey { depth: 1, key: Value::from("é".repeat(100).as_str()) };
		assert!(long.to_string().len() < 120);
	}
}
