# Display names

Status: agreed 2026-09-27 (James). Replaces the `FIELD_SENDER_NAME` (0x10)
mechanism. Applies to LXMF-rust, the iOS FFI crate, the Android JNI crate,
Retichat-ios (app and Notification Service Extension), Retichat-android and
Retichat-js.

The audit that led here (every client, every surface, file:line) found that
names reached almost no screen: iOS decoded 0x10 only as msgpack str while the
router sent bin; the web client never named its DMs; DMs sent as a distro and
all channel posts carried no name; each client stored and ranked names
differently. This document is the single contract all clients implement.

## 1. Three names, all empty by default

| Name | Carried in | Who can read it | Empty means |
|---|---|---|---|
| Announce Display Name | the `lxmf.delivery` announce (device and distro) | the whole network, including Sideband, MeshChat, NomadNet, Columba | the announce carries `nil`: anonymous to other apps |
| Message Display Name | field `0xD1` of LXMF messages (DMs, group messages, group control) | the people you message | no name is sent |
| Channel Display Name | field `0xD1` of the LXMF message inside an RFed channel post | anyone who can read that channel | posts carry no name. It never falls back to the Message Display Name |

The three are independent. None defaults to another. There is no placeholder
name ("Retichat", "Retichat Web"): unset means unset.

DESIGN_PRINCIPLES.md §9 still holds: nothing personal is broadcast unless the
user explicitly fills in the Announce Display Name, which is a separate field
labelled as public.

## 2. Wire format

### 2.1 Field 0xD1: `FIELD_DISPLAY_NAME`

- Key: the integer `0xD1` (msgpack `0xCC 0xD1`). Chosen next to `0xD0`
  (`SF_RFED_DISTRO`, the distro announce flag). Upstream LXMF (1.2.0),
  MeshChatX and Columba do not use it.
- Value: the cleaned name (section 3) as UTF-8 bytes, msgpack **bin**.
  Receivers accept **bin or str**; any other type (map, array, int, nil) is
  treated as absent.
- An empty value (zero-length bin or str) means "I have no name now": the
  receiver clears the name it holds for that sender (subject to section 5.2).
- `0xD1` always names the LXMF **source** of the message that carries it (the
  identity that signed it). It never names `GROUP_SENDER` (0xA4) or anyone else.
- `0x10` is retired: no Retichat client sends or reads it. MeshChatX uses field
  16 for its "app extensions" dict and Columba reads 0x10 as legacy reactions.
  No transition period.

### 2.2 Announce

- Device `lxmf.delivery` announce app_data: `[announce_name, stamp_cost]`,
  where `announce_name` is bin (cleaned UTF-8) or `nil`. This is upstream's
  format, so upstream clients show it.
- Distro announce app_data: `[announce_name, nil, [0xD0]]`, same rule.
- Web client announce: `[announce_name, nil, []]` (its current shape with the
  first slot filled).
- A change to the Announce Display Name updates the app_data of every delivery
  destination immediately; the next announce carries it.

### 2.3 Channel posts

The LXMF message inside the channel envelope carries a fields map. When the
channel rule (section 4.2) says to include the name, the map holds
`{0xD1: <Channel Display Name or empty>}`; otherwise the message has no `0xD1`.
Nothing else about the envelope changes.

**Key binding (required).** Channel unpack must check, before remembering any
key, that the 64-byte public key in the post's prelude produces the claimed
source hash as an `lxmf.delivery` destination (the check in
`retichat_identity_remember_lxmf_delivery`). A post that fails is rejected.
Without this, anyone who knows a channel's name could post as a contact and
overwrite that contact's stored key.

## 3. Cleaning

One definition, implemented once in Rust (`lxmf_rust::display_name::clean`) and
mirrored in Retichat-js. Shared test vectors live in
`LXMF-rust/tests/display_name_vectors.json` and are run by both test suites.
Swift and Kotlin call the Rust function through the FFI/JNI rather than
reimplementing it.

Input: raw bytes. Output: `Some(String)` or `None`.

1. Invalid UTF-8: `None`.
2. Tab, LF, CR and every other Unicode `White_Space` character become U+0020.
3. Remove: C0 controls U+0000–U+001F, U+007F, C1 controls U+0080–U+009F; bidi
   embeddings, overrides and isolates U+202A–U+202E and U+2066–U+2069; U+200B,
   U+200E, U+200F, U+2060, U+FEFF. Keep U+200C and U+200D (needed by some
   scripts and emoji sequences).
4. Collapse runs of spaces to one; trim both ends.
5. Truncate to 64 Unicode scalar values; trim again and drop a trailing U+200D.
6. Empty: `None`.

Senders apply the same function when the user saves a name, so the settings
screen shows exactly what goes out.

Announce names only: a cleaned name equal to "Anonymous Peer"
(case-insensitive) is treated as `None`. It is MeshChatX's and Columba's
placeholder.

Decoding `0xD1` yields one of three states:

| State | When |
|---|---|
| `Absent` | no 0xD1, a non-bin/str value, or a non-empty value that cleans to `None` |
| `Clear` | a zero-length value |
| `Name(s)` | a value that cleans to `Some(s)` |

## 4. When a name is sent

### 4.1 Messages (DMs, groups, group control): the name ledger

The router adds `0xD1`. Apps never set it themselves.

- The router holds one `message_display_name` (cleaned, or none), set at start
  and changed at runtime through a setter. No stack restart.
- It applies to every outbound message whatever its source (device or distro),
  except messages to one's own devices (distro sent-copies §17.11 and distro
  identity transfers §17.9).
- The ledger remembers, per `(source hash, recipient hash)`, the digest of the
  name last **confirmed delivered** and when:
  `SQLite <storagepath>/lxmf/display_names.sqlite3`, table
  `sent_names(source BLOB, recipient BLOB, name_digest BLOB, confirmed_at INTEGER, PRIMARY KEY(source, recipient))`,
  WAL, `synchronous=NORMAL`, as the other SQLite stores. `name_digest` is the
  first 16 bytes of SHA-256 of the cleaned name's UTF-8 (the empty name hashes
  the empty string).
- The decision is made once per message in `handle_outbound`, and the field is
  written into the message, so retries and the propagated copy are
  byte-identical (same message hash).
  - Name set: include it if there is no row, the row's digest differs, or the
    row is older than **30 days** (`NAME_REFRESH_SECS`).
  - Name unset: include an empty `0xD1` only if a row exists whose digest is
    not the empty-name digest (the recipient last got a real name); otherwise
    nothing.
- When a message reaches `DELIVERED`, if it carries `0xD1`, upsert
  `(source, destination, digest(value), now)`.
- The source is part of the key because a distro and a device are different
  contacts to the recipient.
- LXMF gives the sender no delivery confirmation for propagated messages, so a
  recipient reached only through a propagation node keeps getting the name on
  every message. That is intended.

### 4.2 Channel posts: the client rule

Channel posts have no per-reader confirmation. Each client keeps, per channel:
`last_digest` (digest of the name last included, or none),
`last_included_at`, and the set of sender hashes seen in the channel. All of it
is persisted.

A post includes the Channel Display Name when the name is set and any of:

1. `last_digest` differs from the current name's digest (first post, or the
   name changed);
2. a sender not seen before in this channel has posted since
   `last_included_at`;
3. more than **24 hours** have passed since `last_included_at`
   (`CHANNEL_NAME_REFRESH_SECS`). This is the only thing that reaches silent
   readers who joined later.

When the name is unset and `last_digest` is a non-empty name's digest, the next
post carries an empty `0xD1` (clear) once.

After the post is handed to RFed, record `last_digest` and `last_included_at`.

## 5. Receiving

### 5.1 Storage

Per contact (keyed by the hash the messages come from), three separate slots:

- `localName`: the user's own name for the contact. Nullable, and clearable
  from the rename UI (saving an empty value clears it).
- `messageName`: from `0xD1`.
- `announceName`: from the contact's announce (cleaned, "Anonymous Peer" as
  none). Replaced on every announce, and set to none when an announce has no
  name.

Per channel and sender: `channelName`, from `0xD1` in that sender's posts in
that channel. It never becomes the contact's `messageName`.

### 5.2 Accepting a 0xD1

| Signature | `Name(s)` | `Clear` |
|---|---|---|
| validated | `messageName = s` | `messageName = none` |
| source unknown (no key yet) | set only if `messageName` is none | ignore |
| invalid | ignore | ignore |

This applies on every path that yields an LXMF message: direct, opportunistic,
propagated, stream ingest, distro unwrap, iOS NSE import, group messages
(including relayed copies, where it names the relayer, the LXMF source). The
distro unwrap must therefore return the name state and signature validity.

A channel post's `0xD1` is accepted only after the key binding and signature
checks pass, and sets or clears `channelName` for that `(channel, sender)`.

### 5.3 Showing a name

Each client has one resolver, and every surface uses it: chat list,
conversation header, message bubbles, group sender labels, group member lists,
contacts, pickers, chat info, system messages, in-app and background
notifications. No surface stores a resolved name in message text; system
messages keep the hash and resolve it when shown.

- Contact: `localName ?? messageName ?? announceName ?? shortHash`.
- Channel post: `channelName ?? localName ?? messageName ?? announceName ?? shortHash`.
  When the label comes from `channelName`, the 8-hex short hash is shown next to
  it as secondary text. Channel names are public and anyone can pick any name.
- `shortHash` is the first 8 hex characters followed by `…` on every client.

### 5.4 Migrating existing data

Never lose a name the user typed.

- iOS has one `displayName` and no rename flag. A value that is a hash
  placeholder is dropped. A value equal to the contact's recalled announce name
  becomes `announceName`. Anything else becomes `localName`.
- Android: `isNameManual` → `localName`. Otherwise `messageName`, unless it is
  a hash placeholder, which is dropped.
- Web: `nameCustomized` → `localName`. Otherwise `messageName`, unless it is a
  `?hash` placeholder, which is dropped.
- Settings: the old display name becomes the Message Display Name. Android's
  literal "Retichat" and the web's "Retichat Web" placeholders become empty.
  The old channel display name stays the Channel Display Name. The Announce
  Display Name starts empty.

The ledger starts empty, so after the update every sender includes its name
once to each recipient. Names migrated into `messageName` are refreshed that
way.

## 6. Settings

Under the identity section, three fields:

- **Announce Display Name**: "Public. Sent in your announces to the whole
  network, including other Reticulum apps. Leave empty to stay anonymous."
- **Message Display Name**: "Sent inside your messages, only to the people you
  message."
- **Channel Display Name**: "Shown on your channel posts. Anyone who can read a
  channel can see it. Leave empty to post without a name."

Changes take effect at once through the router setters, with no stack restart.

## 7. Related fixes shipped with this

- **Channel key binding**: section 2.3.
- **Web client LXMF signature validation**: Retichat-js never verified LXMF
  signatures (`lxmf_message.js`, `// todo validate signature`), so any name it
  received could be forged. It now computes the same three-way result as the
  native clients (validated, source unknown, invalid).
- **Android privacy filter**: the router's stranger filter was on by default
  with an allowlist nothing filled, so it dropped every router-delivered
  message, contacts' included. Android now accepts exactly what iOS accepts:
  allowlisted contacts, plus group traffic under iOS's group message policy.

## 8. Not in scope (follow-ups)

- A relayed group message names the relayer. The author is resolved from the
  receiver's own contacts through 0xA4.
- Syncing one Message Display Name across a distro's devices. Each device
  sends its own.
- Group membership of distro holders (audit H8), GROUP_SENDER trust (M13),
  link-proven identities (M15), Android's leave message (L5).
