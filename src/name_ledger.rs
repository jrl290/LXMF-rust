//! The name ledger (DISPLAY_NAMES.md §4.1).
//!
//! Remembers, per `(source hash, recipient hash)`, the digest of the name
//! last **confirmed delivered** and when, so the router sends the Message
//! Display Name only when the recipient may not have it: first contact, a
//! changed name, a 30-day refresh, or once after the name was cleared.
//!
//! Storage: `<storagepath>/lxmf/display_names.sqlite3`, one row per
//! `(source, recipient)`, upserted on every DELIVERED that carried the name
//! entry (key 0 of the Retichat field `0xD1`).
//! WAL + `synchronous=NORMAL`, as Reticulum-rust's known destinations store.
//!
//! If the database cannot be opened the router logs it loudly and includes
//! the name on every message: names are never silently dropped.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rmpv::Value;
use rusqlite::{params, Connection, OptionalExtension};

use reticulum_rust::{hexrep, log, LOG_ERROR, LOG_NOTICE};

use crate::display_name::{self, NameField, DIGEST_LEN, NAME_REFRESH_SECS};
use crate::distro::{DISTRO_SENT_TYPE, DISTRO_TRANSFER_TYPE};
use crate::lx_message::LXMessage;
use crate::lxmf::FIELD_CUSTOM_TYPE;
use crate::retichat_field::{self, key_is, RF_DISPLAY_NAME};

pub const LEDGER_FILE_NAME: &str = "display_names.sqlite3";

pub fn unix_now() -> i64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs() as i64)
		.unwrap_or(0)
}

/// One ledger row: what the recipient last confirmed receiving, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRow {
	pub name_digest: Vec<u8>,
	pub confirmed_at: i64,
}

/// §4.1: what an outbound message carries, given the Message Display Name
/// and the ledger row for its `(source, recipient)`.
///
/// - name set: the name when there is no row, the digest differs, or the
///   row is older than `NAME_REFRESH_SECS`; otherwise nothing;
/// - name unset: an empty value (clear) when the row holds a real name's
///   digest; otherwise nothing.
pub fn decide(message_name: Option<&str>, row: Option<&LedgerRow>, now: i64) -> NameField {
	match message_name {
		Some(name) => {
			let fresh = row.map_or(false, |row| {
				row.name_digest[..] == display_name::digest(Some(name))[..]
					&& now - row.confirmed_at <= NAME_REFRESH_SECS
			});
			if fresh {
				NameField::Absent
			} else {
				NameField::Name(name.to_string())
			}
		}
		None => match row {
			Some(row) if row.name_digest[..] != display_name::empty_digest()[..] => NameField::Clear,
			_ => NameField::Absent,
		},
	}
}

/// §4.1: messages to one's own devices carry no name — distro sent-copies
/// (RFed SPEC §17.11) and distro identity transfers (§17.9), recognised by
/// their `FIELD_CUSTOM_TYPE`.
pub fn is_own_devices_message(fields: &Value) -> bool {
	let Value::Map(entries) = fields else { return false };
	entries.iter().any(|(key, value)| {
		key_is(key, FIELD_CUSTOM_TYPE)
			&& match value {
				Value::String(s) => matches!(s.as_str(), Some(DISTRO_SENT_TYPE) | Some(DISTRO_TRANSFER_TYPE)),
				Value::Binary(b) => b == DISTRO_SENT_TYPE.as_bytes() || b == DISTRO_TRANSFER_TYPE.as_bytes(),
				_ => false,
			}
	})
}

/// `(source, recipient, digest)` to upsert when this outbound message is
/// DELIVERED: present only when it carries a bin/str name entry (key 0 of
/// the `0xD1` map).
pub fn delivery_record(message: &LXMessage) -> Option<(Vec<u8>, Vec<u8>, [u8; DIGEST_LEN])> {
	let value = retichat_field::read_entry(&message.fields, RF_DISPLAY_NAME)?;
	let raw: &[u8] = match value {
		Value::Binary(bytes) => bytes,
		Value::String(string) => string.as_bytes(),
		_ => return None,
	};
	let text = std::str::from_utf8(raw).ok()?;
	let name = if text.is_empty() { None } else { Some(text) };
	Some((message.source_hash.clone(), message.destination_hash.clone(), display_name::digest(name)))
}

pub struct NameLedger {
	path: PathBuf,
	/// `None` when the database could not be opened: every message then
	/// carries the name (see `prepare_outbound`).
	conn: Option<Mutex<Connection>>,
}

impl NameLedger {
	/// Open (or create) `<dir>/display_names.sqlite3`. `dir` is the router's
	/// storage path, which already ends in `/lxmf`. Failure is logged loudly
	/// and leaves a ledger that includes the name on every message.
	pub fn open(dir: &str) -> Self {
		let path = Path::new(dir).join(LEDGER_FILE_NAME);
		let opened = std::fs::create_dir_all(dir)
			.map_err(|e| format!("could not create {dir}: {e}"))
			.and_then(|()| Self::open_db(&path));
		match opened {
			Ok(conn) => NameLedger { path, conn: Some(Mutex::new(conn)) },
			Err(e) => {
				let message = format!(
					"DISPLAY NAME LEDGER UNAVAILABLE: {} could not be opened ({e}). \
					 The Message Display Name will be sent on EVERY message until this is fixed.",
					path.display()
				);
				log(&message, LOG_ERROR, false, false);
				eprintln!("[LXMF] {message}");
				NameLedger { path, conn: None }
			}
		}
	}

	fn open_db(path: &Path) -> Result<Connection, String> {
		let conn = Connection::open(path).map_err(|e| e.to_string())?;
		conn.busy_timeout(Duration::from_secs(2)).map_err(|e| e.to_string())?;
		conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(())).map_err(|e| e.to_string())?;
		conn.execute_batch(
			"PRAGMA synchronous=NORMAL;
			 CREATE TABLE IF NOT EXISTS sent_names (
			     source       BLOB NOT NULL,
			     recipient    BLOB NOT NULL,
			     name_digest  BLOB NOT NULL,
			     confirmed_at INTEGER NOT NULL,
			     PRIMARY KEY (source, recipient)
			 );",
		)
		.map_err(|e| e.to_string())?;
		// A file that is not a database fails here, not on first use.
		conn.query_row("SELECT count(*) FROM sent_names", [], |_| Ok(())).map_err(|e| e.to_string())?;
		Ok(conn)
	}

	pub fn is_open(&self) -> bool {
		self.conn.is_some()
	}

	pub fn path(&self) -> &Path {
		&self.path
	}

	pub fn lookup(&self, source: &[u8], recipient: &[u8]) -> Result<Option<LedgerRow>, String> {
		let conn = self.conn.as_ref().ok_or("ledger not open")?;
		let conn = conn.lock().map_err(|_| "ledger lock poisoned".to_string())?;
		conn.query_row(
			"SELECT name_digest, confirmed_at FROM sent_names WHERE source = ?1 AND recipient = ?2",
			params![source, recipient],
			|row| Ok(LedgerRow { name_digest: row.get(0)?, confirmed_at: row.get(1)? }),
		)
		.optional()
		.map_err(|e| e.to_string())
	}

	pub fn record(&self, source: &[u8], recipient: &[u8], name_digest: &[u8], confirmed_at: i64) -> Result<(), String> {
		let conn = self.conn.as_ref().ok_or("ledger not open")?;
		let conn = conn.lock().map_err(|_| "ledger lock poisoned".to_string())?;
		conn.execute(
			"INSERT INTO sent_names (source, recipient, name_digest, confirmed_at) VALUES (?1, ?2, ?3, ?4)
			 ON CONFLICT(source, recipient) DO UPDATE SET name_digest = excluded.name_digest, confirmed_at = excluded.confirmed_at",
			params![source, recipient, name_digest, confirmed_at],
		)
		.map(|_| ())
		.map_err(|e| e.to_string())
	}

	/// §4.1, once per message, before its first pack: write the decision
	/// into `message.fields`. A message already decided (a resend, or a
	/// `propagated_copy` of a decided message) or already packed is left
	/// exactly as it is, so every copy has the same bytes and hash.
	pub fn prepare_outbound(&self, message_name: Option<&str>, message: &mut LXMessage, now: i64) {
		if message.display_name_decided {
			return;
		}
		message.display_name_decided = true;
		if message.packed.is_some() {
			return;
		}
		// Apps never set the name entry (§4.1): the router's decision is the
		// only one. Only key 0 is touched; the app's other Retichat entries
		// stay, and an emptied map (or a non-map 0xD1) is dropped.
		message.remove_retichat_entry(RF_DISPLAY_NAME);
		if is_own_devices_message(&message.fields) {
			return;
		}
		let decision = if self.is_open() {
			match self.lookup(&message.source_hash, &message.destination_hash) {
				Ok(row) => decide(message_name, row.as_ref(), now),
				Err(e) => {
					log(
						&format!(
							"DISPLAY NAME LEDGER lookup failed for {} -> {} ({e}); including the name",
							hexrep(&message.source_hash, false),
							hexrep(&message.destination_hash, false)
						),
						LOG_ERROR,
						false,
						false,
					);
					decide(message_name, None, now)
				}
			}
		} else {
			// No ledger: include a set name every time. An unset name has
			// nothing to send, and without a ledger there is no record that
			// the recipient ever had one to clear.
			decide(message_name, None, now)
		};
		if let Some(value) = decision.to_value() {
			message.set_retichat_entry(RF_DISPLAY_NAME, value);
		}
	}

	/// §4.1: the message reached DELIVERED; if it carries the name entry, record it.
	pub fn record_delivered(&self, message: &LXMessage, now: i64) {
		if let Some(record) = delivery_record(message) {
			self.record_delivery(&record, now);
		}
	}

	pub fn record_delivery(&self, record: &(Vec<u8>, Vec<u8>, [u8; DIGEST_LEN]), now: i64) {
		if !self.is_open() {
			return;
		}
		let (source, recipient, digest) = record;
		match self.record(source, recipient, digest, now) {
			Ok(()) => log(
				&format!("Display name confirmed delivered {} -> {}", hexrep(source, false), hexrep(recipient, false)),
				LOG_NOTICE,
				false,
				false,
			),
			Err(e) => log(
				&format!(
					"DISPLAY NAME LEDGER could not record delivery {} -> {} ({e}); the name will be sent again",
					hexrep(source, false),
					hexrep(recipient, false)
				),
				LOG_ERROR,
				false,
				false,
			),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::display_name::decode_field;
	use reticulum_rust::destination::{Destination, DestinationType};
	use reticulum_rust::identity::Identity;

	const DAY: i64 = 24 * 60 * 60;

	fn temp_dir(label: &str) -> String {
		let mut bytes = [0u8; 8];
		rand::Rng::fill(&mut rand::thread_rng(), &mut bytes);
		let dir = std::env::temp_dir().join(format!("lxmf-name-ledger-{label}-{}", hexrep(&bytes, false)));
		dir.to_string_lossy().into_owned()
	}

	fn delivery(identity: Identity, inbound: bool) -> Destination {
		if inbound {
			Destination::new_inbound(Some(identity), DestinationType::Single, "lxmf".into(), vec!["delivery".into()]).unwrap()
		} else {
			Destination::new_outbound(Some(identity), DestinationType::Single, "lxmf".into(), vec!["delivery".into()]).unwrap()
		}
	}

	struct Pair {
		source: Destination,
		recipient: Destination,
	}

	fn pair() -> Pair {
		Pair { source: delivery(Identity::new(true), true), recipient: delivery(Identity::new(true), false) }
	}

	fn message(pair: &Pair, fields: Option<Value>) -> LXMessage {
		LXMessage::new(
			Some(pair.recipient.clone()),
			Some(pair.source.clone()),
			Some(b"hello".to_vec()),
			Some(Vec::new()),
			fields,
			Some(LXMessage::DIRECT),
			None,
			None,
			None,
			false,
		)
		.unwrap()
	}

	/// Send one message through the ledger and deliver it; returns what it carried.
	fn send(ledger: &NameLedger, pair: &Pair, name: Option<&str>, now: i64, delivered: bool) -> NameField {
		let mut lxm = message(pair, None);
		ledger.prepare_outbound(name, &mut lxm, now);
		if delivered {
			ledger.record_delivered(&lxm, now);
		}
		decode_field(&lxm.fields)
	}

	#[test]
	fn first_send_includes_and_a_confirmed_recipient_is_skipped() {
		let ledger = NameLedger::open(&temp_dir("first"));
		assert!(ledger.is_open());
		let p = pair();
		assert_eq!(send(&ledger, &p, Some("Alice"), 1_000, true), NameField::Name("Alice".into()));
		assert_eq!(send(&ledger, &p, Some("Alice"), 1_001, true), NameField::Absent, "confirmed: not sent again");
		// Another recipient has not had it.
		let q = Pair { source: p.source.clone(), recipient: delivery(Identity::new(true), false) };
		assert_eq!(send(&ledger, &q, Some("Alice"), 1_002, true), NameField::Name("Alice".into()));
	}

	#[test]
	fn an_unconfirmed_send_is_sent_again() {
		let ledger = NameLedger::open(&temp_dir("unconfirmed"));
		let p = pair();
		assert_eq!(send(&ledger, &p, Some("Alice"), 1_000, false), NameField::Name("Alice".into()));
		assert_eq!(send(&ledger, &p, Some("Alice"), 1_001, false), NameField::Name("Alice".into()),
			"no DELIVERED (e.g. propagated): the name goes on every message");
	}

	#[test]
	fn a_name_change_is_sent() {
		let ledger = NameLedger::open(&temp_dir("change"));
		let p = pair();
		send(&ledger, &p, Some("Alice"), 1_000, true);
		assert_eq!(send(&ledger, &p, Some("Alicia"), 1_001, true), NameField::Name("Alicia".into()));
		assert_eq!(send(&ledger, &p, Some("Alicia"), 1_002, true), NameField::Absent);
	}

	#[test]
	fn the_name_is_refreshed_after_thirty_days() {
		let ledger = NameLedger::open(&temp_dir("refresh"));
		let p = pair();
		let t0 = 10_000_000;
		send(&ledger, &p, Some("Alice"), t0, true);
		assert_eq!(send(&ledger, &p, Some("Alice"), t0 + 30 * DAY, false), NameField::Absent, "exactly 30 days is not older");
		assert_eq!(send(&ledger, &p, Some("Alice"), t0 + 30 * DAY + 1, true), NameField::Name("Alice".into()));
		assert_eq!(send(&ledger, &p, Some("Alice"), t0 + 30 * DAY + 2, true), NameField::Absent, "refresh confirmed");
	}

	#[test]
	fn a_cleared_name_sends_empty_once_then_nothing() {
		let ledger = NameLedger::open(&temp_dir("clear"));
		let p = pair();
		send(&ledger, &p, Some("Alice"), 1_000, true);
		assert_eq!(send(&ledger, &p, None, 1_001, false), NameField::Clear, "unconfirmed clear is repeated");
		assert_eq!(send(&ledger, &p, None, 1_002, true), NameField::Clear);
		assert_eq!(send(&ledger, &p, None, 1_003, true), NameField::Absent, "the clear was confirmed");
		assert_eq!(send(&ledger, &p, Some("Alice"), 1_004, true), NameField::Name("Alice".into()), "set again after a clear");
	}

	#[test]
	fn a_never_named_recipient_gets_nothing_when_unset() {
		let ledger = NameLedger::open(&temp_dir("never"));
		let p = pair();
		assert_eq!(send(&ledger, &p, None, 1_000, true), NameField::Absent);
		assert_eq!(ledger.lookup(&p.source.hash, &p.recipient.hash).unwrap(), None, "nothing carried, nothing recorded");
	}

	#[test]
	fn the_source_is_part_of_the_key() {
		let ledger = NameLedger::open(&temp_dir("source"));
		let device = pair();
		send(&ledger, &device, Some("Alice"), 1_000, true);
		let distro = Pair { source: delivery(Identity::new(true), true), recipient: device.recipient.clone() };
		assert_eq!(send(&ledger, &distro, Some("Alice"), 1_001, true), NameField::Name("Alice".into()),
			"a distro and a device are different contacts to the recipient");
	}

	#[test]
	fn the_ledger_survives_a_restart() {
		let dir = temp_dir("restart");
		let p = pair();
		send(&NameLedger::open(&dir), &p, Some("Alice"), 1_000, true);
		assert_eq!(send(&NameLedger::open(&dir), &p, Some("Alice"), 1_001, true), NameField::Absent);
		assert!(Path::new(&dir).join(LEDGER_FILE_NAME).exists());
	}

	/// §4.1: decided once, before the first pack. A resend and the
	/// propagated clone carry the same fields and have the same hash even
	/// when the ledger changed in between.
	#[test]
	fn the_propagated_clone_has_identical_fields_and_hash() {
		let ledger = NameLedger::open(&temp_dir("clone"));
		let p = pair();
		let mut direct = message(&p, None);
		ledger.prepare_outbound(Some("Alice"), &mut direct, 1_000);
		direct.pack(false).unwrap();
		assert_eq!(decode_field(&direct.fields), NameField::Name("Alice".into()));

		// Another message to the same recipient is confirmed meanwhile, so a
		// fresh decision would now omit the name.
		send(&ledger, &p, Some("Alice"), 1_001, true);

		let mut clone = direct.propagated_copy().unwrap();
		ledger.prepare_outbound(Some("Alice"), &mut clone, 1_002);
		assert_eq!(clone.fields, direct.fields);
		clone.pack(false).unwrap();
		assert_eq!(clone.hash, direct.hash);

		// A resend of the same message object is untouched as well.
		let before = direct.fields.clone();
		ledger.prepare_outbound(Some("Bob"), &mut direct, 1_003);
		assert_eq!(direct.fields, before);
	}

	fn pack(value: &Value) -> Vec<u8> {
		let mut buf = Vec::new();
		rmpv::encode::write_value(&mut buf, value).unwrap();
		buf
	}

	/// `{0xD1: {entries}}`, as an app would build it.
	fn retichat(entries: Vec<(i64, Value)>) -> Value {
		Value::Map(vec![(
			Value::from(0xD1),
			Value::Map(entries.into_iter().map(|(k, v)| (Value::from(k), v)).collect()),
		)])
	}

	#[test]
	fn a_name_set_by_the_app_is_replaced_by_the_decision() {
		let ledger = NameLedger::open(&temp_dir("appset"));
		let p = pair();
		send(&ledger, &p, Some("Alice"), 1_000, true);
		let mut lxm = message(&p, Some(retichat(vec![(0, Value::Binary(b"Mallory".to_vec()))])));
		ledger.prepare_outbound(Some("Alice"), &mut lxm, 1_001);
		assert_eq!(decode_field(&lxm.fields), NameField::Absent);
		assert_eq!(pack(&lxm.fields), vec![0x80], "no empty 0xD1 map is left behind");

		// The unshipped bin form (not a map) carries nothing and is dropped.
		let mut lxm = message(&p, Some(Value::Map(vec![(Value::from(0xD1), Value::Binary(b"Mallory".to_vec()))])));
		ledger.prepare_outbound(Some("Alice"), &mut lxm, 1_002);
		assert_eq!(pack(&lxm.fields), vec![0x80]);
	}

	/// §4.1: the router adds or removes only key 0; the app's other Retichat
	/// entries (e.g. group entries after the §10 switch) survive, and key 0
	/// goes first in the map.
	#[test]
	fn app_entries_survive_the_decision() {
		let ledger = NameLedger::open(&temp_dir("appentries"));
		let p = pair();
		let app = || retichat(vec![(4, Value::String("leave".into())), (0, Value::Binary(b"Mallory".to_vec()))]);

		let mut named = message(&p, Some(app()));
		ledger.prepare_outbound(Some("Alice"), &mut named, 1_000);
		assert_eq!(
			pack(&named.fields),
			vec![0x81, 0xcc, 0xd1, 0x82, 0x00, 0xc4, 0x05, b'A', b'l', b'i', b'c', b'e', 0x04, 0xa5, b'l', b'e', b'a', b'v', b'e']
		);
		ledger.record_delivered(&named, 1_000);

		// Confirmed: no name this time, the app's entry stays.
		let mut unnamed = message(&p, Some(app()));
		ledger.prepare_outbound(Some("Alice"), &mut unnamed, 1_001);
		assert_eq!(pack(&unnamed.fields), vec![0x81, 0xcc, 0xd1, 0x81, 0x04, 0xa5, b'l', b'e', b'a', b'v', b'e']);
		assert_eq!(delivery_record(&unnamed), None, "no name entry, nothing to record");

		// A clear goes in beside the app's entry.
		let mut cleared = message(&p, Some(app()));
		ledger.prepare_outbound(None, &mut cleared, 1_002);
		assert_eq!(pack(&cleared.fields), vec![0x81, 0xcc, 0xd1, 0x82, 0x00, 0xc4, 0x00, 0x04, 0xa5, b'l', b'e', b'a', b'v', b'e']);
		let (_, _, digest) = delivery_record(&cleared).unwrap();
		assert_eq!(digest, display_name::empty_digest());

		// Decided once: the propagated copy of a message with app entries
		// keeps the same map and the same hash.
		let mut direct = message(&p, Some(app()));
		ledger.prepare_outbound(Some("Alicia"), &mut direct, 1_003);
		direct.pack(false).unwrap();
		let mut clone = direct.propagated_copy().unwrap();
		ledger.prepare_outbound(Some("Alicia"), &mut clone, 1_004);
		assert_eq!(clone.fields, direct.fields);
		clone.pack(false).unwrap();
		assert_eq!(clone.hash, direct.hash);
	}

	/// §4.1: the ledger records what key 0 of the map says; a top-level
	/// bin at 0xD1 (never shipped) is not a name.
	#[test]
	fn the_delivery_record_reads_key_0() {
		let p = pair();
		let named = message(&p, Some(retichat(vec![(0, Value::String("Alice".into()))])));
		let (source, recipient, digest) = delivery_record(&named).unwrap();
		assert_eq!((source, recipient), (p.source.hash.clone(), p.recipient.hash.clone()));
		assert_eq!(digest, display_name::digest(Some("Alice")));
		let bin_form = message(&p, Some(Value::Map(vec![(Value::from(0xD1), Value::Binary(b"Alice".to_vec()))])));
		assert_eq!(delivery_record(&bin_form), None);
		let other_type = message(&p, Some(retichat(vec![(0, Value::from(7))])));
		assert_eq!(delivery_record(&other_type), None);
	}

	#[test]
	fn distro_sent_copies_and_transfers_carry_no_name() {
		let ledger = NameLedger::open(&temp_dir("exclusions"));
		let p = pair();
		for custom_type in [DISTRO_SENT_TYPE, DISTRO_TRANSFER_TYPE] {
			for value in [Value::String(custom_type.into()), Value::Binary(custom_type.as_bytes().to_vec())] {
				let fields = Value::Map(vec![(Value::from(FIELD_CUSTOM_TYPE as i64), value)]);
				let mut lxm = message(&p, Some(fields));
				ledger.prepare_outbound(Some("Alice"), &mut lxm, 1_000);
				assert_eq!(decode_field(&lxm.fields), NameField::Absent, "{custom_type}");
				ledger.record_delivered(&lxm, 1_000);
			}
		}
		assert_eq!(ledger.lookup(&p.source.hash, &p.recipient.hash).unwrap(), None);
		// Another custom type is an ordinary message.
		let fields = Value::Map(vec![(Value::from(FIELD_CUSTOM_TYPE as i64), Value::String("something.else".into()))]);
		let mut lxm = message(&p, Some(fields));
		ledger.prepare_outbound(Some("Alice"), &mut lxm, 1_000);
		assert_eq!(decode_field(&lxm.fields), NameField::Name("Alice".into()));
	}

	/// The retired 0x10 is never written.
	#[test]
	fn no_sender_name_field_is_written() {
		let ledger = NameLedger::open(&temp_dir("no0x10"));
		let p = pair();
		let mut lxm = message(&p, None);
		ledger.prepare_outbound(Some("Alice"), &mut lxm, 1_000);
		let Value::Map(entries) = &lxm.fields else { panic!("fields must be a map") };
		assert!(entries.iter().all(|(k, _)| !key_is(k, 0x10)));
		assert_eq!(entries.len(), 1);
	}

	#[test]
	fn an_unopenable_ledger_includes_the_name_on_every_message() {
		// A regular file where the directory should be.
		let blocker = temp_dir("blocked");
		std::fs::write(&blocker, b"not a directory").unwrap();
		let ledger = NameLedger::open(&blocker);
		assert!(!ledger.is_open());
		let p = pair();
		for t in 0..3 {
			assert_eq!(send(&ledger, &p, Some("Alice"), 1_000 + t, true), NameField::Name("Alice".into()));
		}
		assert_eq!(send(&ledger, &p, None, 2_000, true), NameField::Absent);
		let _ = std::fs::remove_file(&blocker);
	}

	#[test]
	fn a_corrupt_database_is_reported_not_used() {
		let dir = temp_dir("corrupt");
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::write(Path::new(&dir).join(LEDGER_FILE_NAME), vec![0x42u8; 4096]).unwrap();
		let ledger = NameLedger::open(&dir);
		assert!(!ledger.is_open());
		assert_eq!(send(&ledger, &pair(), Some("Alice"), 1_000, true), NameField::Name("Alice".into()));
	}
}
