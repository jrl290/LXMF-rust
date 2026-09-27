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
| Message Display Name | key 0 of the Retichat field `0xD1` in LXMF messages (DMs, group messages, group control) | the people you message | no name is sent |
| Channel Display Name | key 0 of the Retichat field `0xD1` in the LXMF message inside an RFed channel post | anyone who can read that channel | posts carry no name. It never falls back to the Message Display Name |

The three are independent. None defaults to another. There is no placeholder
name ("Retichat", "Retichat Web"): unset means unset.

DESIGN_PRINCIPLES.md §9 still holds: nothing personal is broadcast unless the
user explicitly fills in the Announce Display Name, which is a separate field
labelled as public.

## 2. Wire format

### 2.1 The Retichat field 0xD1 and its name entry

Retichat owns **one** LXMF field number, `0xD1` (`FIELD_RETICHAT`, msgpack
`0xCC 0xD1`), chosen next to `0xD0` (`SF_RFED_DISTRO`, the distro announce
flag). Upstream LXMF (1.2.0), MeshChatX and Columba do not use it. Its value is
a msgpack **map** whose keys are small non-negative integers (one byte each on
the wire); section 10 lists them. Everything Retichat-specific that is not a
distro marker lives there (distro markers use upstream's generic
`FIELD_CUSTOM_*` slots, which take no field number of ours). A `0xD1` that is
not a map is ignored whole; unknown keys inside it are ignored. A message with
no Retichat entries carries no `0xD1` at all.

The display name is **key 0** (`RF_DISPLAY_NAME`):

- Value: the cleaned name (section 3) as UTF-8 bytes, msgpack **bin**.
  Receivers accept **bin or str**; any other type (map, array, int, nil) is
  treated as absent.
- An empty value (zero-length bin or str) means "I have no name now": the
  receiver clears the name it holds for that sender (subject to section 5.2).
- Key 0 always names the LXMF **source** of the message that carries it (the
  identity that signed it). It never names the group sender (key 5 / 0xA4) or
  anyone else.
- `0x10` is retired: no Retichat client sends or reads it. MeshChatX uses field
  16 for its "app extensions" dict and Columba reads 0x10 as legacy reactions.
  No transition period.

Elsewhere in this document "`0xD1`" as a name means key 0 of this field.

### 2.2 Announce

- Device `lxmf.delivery` announce app_data: `[announce_name, stamp_cost]`,
  where `announce_name` is bin (cleaned UTF-8) or `nil`. Upstream LXMF 1.2.0
  announces `[display_name, stamp_cost, [supported functionality]]` and every
  upstream client reads the name from index 0, so they show it.
- Distro announce app_data: `[announce_name, nil, [0xD0]]`, same rule.
- Web client announce: `[announce_name, nil, []]` (its current shape with the
  first slot filled).
- A change to the Announce Display Name updates the app_data of every delivery
  destination immediately; the next announce carries it.

### 2.3 Channel posts

The LXMF message inside the channel envelope carries a fields map. When the
channel rule (section 4.2) says to include the name, the map holds
`{0xD1: {0: <Channel Display Name or empty>}}`; otherwise the message has no
`0xD1`.
Nothing else about the envelope changes.

**Key binding (required).** Channel unpack must check, before remembering any
key, that the 64-byte public key in the post's prelude produces the claimed
source hash as an `lxmf.delivery` destination (`channel::unpack`, and
`channelLxmUnpack` in Retichat-js). A post that fails is rejected.
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

The router writes key 0 of the Retichat field. Apps never set key 0; they may
put other entries in the field (section 10), and the router merges key 0 into
that map (adding or removing only key 0, and dropping the field when the map
ends up empty).

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
- `messageName`: from `0xD1`, with `messageNameAt`, the LXMF timestamp of
  the message that last set or cleared it (section 5.2).
- `announceName`: from the contact's announce (cleaned, "Anonymous Peer" as
  none). Replaced on every announce, and set to none when an announce has no
  name.

- `legacyName`: only on Android and web, holding a name migrated from before
  this design whose origin is unknown (section 5.4). Never written afterwards,
  and dropped as soon as a `0xD1` is accepted for the contact or an announce
  carrying a name arrives.

Per channel and sender: `channelName`, from `0xD1` in that sender's posts in
that channel, with the post timestamp that last set or cleared it. It never
becomes the contact's `messageName`.

### 5.2 Accepting a 0xD1

| Signature | `Name(s)` | `Clear` |
|---|---|---|
| validated | `messageName = s` | `messageName = none` |
| source unknown (no key yet) | set only if `messageName` is none | ignore |
| invalid | ignore | ignore |

Order: a `Name` or `Clear` is accepted only from a message whose LXMF
timestamp is newer than `messageNameAt`; accepting a **validated** one records
that timestamp (a repeat of the current name also advances it). A
source-unknown fill leaves `messageNameAt` as it was: its timestamp is the
sender's unverifiable claim, and recording it would let a forged far-future
message lock out every later validated name. A timestamp that is not a finite
number is never accepted. Messages arrive out of order
(a propagated copy can land after a later direct one), and without this an old
name would overwrite a new one that the sender's ledger then never resends.
Channel names follow the same rule per `(channel, sender)` with the post
timestamp.

This applies on every path that yields an LXMF message: direct, opportunistic,
propagated, stream ingest, distro unwrap, iOS NSE import, group messages
(including relayed copies, where it names the relayer, the LXMF source). The
distro unwrap must therefore return the name state and signature validity.

A channel post's `0xD1` is accepted only after the key binding and signature
checks pass, and sets or clears `channelName` for that `(channel, sender)`.
Posts whose signature is not validated are dropped whole, as all three clients
already did before this design.

### 5.3 Showing a name

Each client has one resolver, and every surface uses it: chat list,
conversation header, message bubbles, group sender labels, group member lists,
contacts, pickers, chat info, system messages, in-app and background
notifications. No surface stores a resolved name in message text; system
messages keep the hash and resolve it when shown.

- Contact: `localName ?? messageName ?? announceName ?? legacyName ?? shortHash`.
- Channel post: a main label and an optional secondary (grey) text. Channel
  names are public and anyone can pick any name, so a channel name never stands
  alone:

  | The poster has | Main label | Secondary |
  |---|---|---|
  | a `channelName` and a `localName` | `localName` | `channelName` |
  | a `channelName`, no `localName` | `channelName` | `shortHash` |
  | no `channelName` | `localName ?? messageName ?? announceName ?? legacyName ?? shortHash` | none |

  (James, 2026-09-27: the user's own name for someone is the name they know them
  by; the channel name moves to the grey spot.) Notifications for channel posts
  name the poster the same way, main label then secondary text
  (`Mum · Night Owl`, `Night Owl · 1a2b3c4d…`), so a channel name never stands
  alone there either.
- `shortHash` is the first 8 hex characters followed by `…` on every client.

### 5.4 Migrating existing data

Never lose a name the user typed.

Placeholders, dropped wherever the name was not typed by the user:
"Retichat", "Retichat Web", "Anonymous Peer" (case-insensitive), and hash
forms (8 to 32 hex, with or without `?` or `…`). Where a name may have been
typed (every iOS name, Android DM chat names, web customized names), a hash
form counts only when it prefixes the contact's own hash; other hex such as
"deadbeef" is kept. Unnamed Android and web senders used
to send the first two as names, and MeshChatX, Columba and lxmd announce the
third.

- iOS has one `displayName` and no rename flag. A placeholder is dropped. A
  value equal to the contact's recalled announce name becomes `announceName`.
  Anything else becomes `localName` (it may have been typed).
- Android: `isNameManual` → `localName`; a DM chat name the user set on a chat
  with no manual contact name → `localName`. Otherwise `legacyName`, unless a
  placeholder.
- Web: `nameCustomized` → `localName`. Otherwise `legacyName`, unless a
  placeholder.

`legacyName` rather than `messageName`, because an old name may have come from
an announce: an upstream contact never sends `0xD1`, so a stale name in
`messageName` would outrank its current announce name for good.
- Settings: the old display name becomes the Message Display Name. Android's
  literal "Retichat" and the web's "Retichat Web" placeholders become empty.
  The old channel display name stays the Channel Display Name. The Announce
  Display Name starts empty.

The ledger starts empty, so after the update every sender includes its name
once to each recipient, which replaces a `legacyName`.

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

## 9. Implementation

Where each part of this contract lives, by function (not line). Rust side:
LXMF-rust `daa71d8`, `72458d2`, `9a2f674` (with Reticulum-rust `c4292f3`).
Apps: Retichat-ios `de38780`, `8e9c8d4`, `fe5f70b`; Retichat-android
`9a39c12` to `59a9c67`; Retichat-js `9c9757a` to `9e991f1`. Checked against
the code in the consistency pass of 2026-09-27.

The one Retichat field (§2.1 map, §10): LXMF-rust `f4d0123`, `ec54084`,
`975854d`; Retichat-ios `097b148` (FFI setters), `d1fcff4`, `8ffcd00`;
Retichat-android `e7e69fd` (JNI setters), `98f28b1`; Retichat-js `d713728`.
Cross-client pass of 2026-09-27: 3,007 random fields maps (both forms,
conflicting values, wrong types, every integer width, str and negative keys,
non-map `0xD1`) and 4,398 encoder outputs were read identically by the Rust,
Swift, Kotlin, JS and Python readers; the Rust, Swift-via-FFI, Kotlin-via-JNI,
JS and Python writers produced identical bytes in both forms.

Every client holds the same switch constant, `false` until the switch (§10):
LXMF-rust `retichat_field::GROUP_ENTRIES_IN_RETICHAT_FIELD`, Swift
`RetichatField.groupEntriesInRetichatField`, Kotlin
`LxmfFields.GROUP_ENTRIES_IN_RETICHAT_FIELD`, JS
`GROUP_ENTRIES_IN_RETICHAT_FIELD` (`lib/retichat_field.js`), Python
`LXMF.GROUP_ENTRIES_IN_RETICHAT_FIELD`. Each client has a test that pins it
false, which is flipped with it. The Swift test also reads the Rust constant
from source, so the two change together. Every client runs the shared
vectors `LXMF-rust/tests/retichat_field_vectors.json`: Rust
`tests/retichat_field_vectors.rs`, Swift `tests/RetichatFieldTests.swift`,
Kotlin `bridge/RetichatFieldVectorsTest`, JS `retichat_field.test.mjs`, Python
`tests/test_display_names.py`.

### Shared Rust (LXMF-rust, used by iOS and Android)

- Field and cleaning (§2.1, §3): `lxmf::FIELD_RETICHAT` (0xD1) and the
  `retichat_field` module (key constants `RF_*`, `read_entry` / `set_entry` /
  `remove_entry`, the §10 group helpers; vectors
  `tests/retichat_field_vectors.json`, run by
  `tests/retichat_field_vectors.rs`); `display_name::clean`, `clean_announce`, `digest`, `decode_field` /
  `decode_fields_bytes` (the three states as `NameField`). Vectors:
  `tests/display_name_vectors.json`, run by `tests/display_name_vectors.rs`.
- Announce (§2.2): `LXMRouter::get_announce_app_data` and
  `set_announce_display_name`; `distro::distro_announce_app_data` /
  `announce_payload`; `announce_name_from_app_data` for received announces.
  `set_announce_display_name` also rewrites Transport's registered copy of
  each delivery destination (`Transport::update_registered_default_app_data`),
  so path responses for an unpublished destination (the iOS NSE) carry it.
- Message send rule (§4.1): `LXMRouter::prepare_display_name`, called once in
  `handle_outbound`; `name_ledger::decide` and `NameLedger::prepare_outbound`;
  delivery confirmation recorded by `NameLedger::record_delivered` /
  `record_delivery`; own-devices exclusion in
  `name_ledger::is_own_devices_message`.
- Accept inputs (§5.2): the delivery callback carries `signature_valid` and
  `unverified_reason` (0 validated, 1 source unknown, 2 invalid;
  `ffi::ReceivedMessage`), plus the raw fields for the app to decode;
  `distro::unwrap_blob` returns `display_name`, `signature_validated` and
  `unverified_reason`. The §5.2 table itself is applied in each app.
- Channel posts (§2.3, §5.2): `channel::pack` (writes 0xD1 from a
  `PostName`) and `channel::unpack`, which checks the key binding with
  `channel::lxmf_delivery_hash_for_public_key` before remembering the key
  (the check §2.3 attributes to `retichat_identity_remember_lxmf_delivery`)
  and reports the name only when the signature validated.
- Retichat field writes (§10): `LXMessage::set_retichat_entry` /
  `remove_retichat_entry`; the app setters `ffi::message_set_retichat_string`
  / `_bool` (C `lxmf_message_set_retichat_string` / `_bool`), which take keys
  1–127 only and give group keys their own type (`retichat_field::app_key`,
  `check_app_entry`). The generic setters `message_add_field_string` / `_bool`
  (C `lxmf_message_add_field` / `_bool`) refuse `0xD1`, so no app can write a
  top-level bin or str there. Host integers never truncate onto a field number
  (`ffi::field_key`). `NameLedger::prepare_outbound` removes key 0 and then
  sets it, leaving the app's other entries in place.
- Bindings: C `lxmf_client_set_message_display_name`,
  `lxmf_client_set_announce_display_name`, `lxmf_display_name_clean`,
  `lxmf_display_name_decode` (`cffi.rs`); iOS `retichat_channel_lxm_pack` /
  `_unpack`, `retichat_distro_unwrap`, `retichat_distro_announce_payload`
  (`retichat-ffi`); Android `nativeRouterSet{Message,Announce}DisplayName`,
  `nativeDisplayName{Clean,Decode}`, `nativeChannelLxm{Pack,Unpack}`,
  `nativeDistro{Unwrap,AnnouncePayload}`,
  `nativeMessageSetRetichat{String,Bool}` (`retichat-jni`).

### Per client

Final pass (2026-09-27): Retichat-ios `6b5e5c7`, `c720698`, `5e7fb69`,
`e387e51`; Retichat-android `16765e6`, `f9d8e53` and the legacy/ordering
commits before them; Retichat-js `7fc07a5`, `f2052f8`. Ordering (§5.2):
iOS `DisplayNames.isNewer` / `acceptMessageName(... currentAt:messageTime:)`
(`Change.fill` for a source-unknown name), `ContactEntity.messageNameAt`;
Android `DisplayNames.recordsMessageTime`, `NameSql.ACCEPT_MESSAGE_NAME`;
web `acceptMessageNameAt`, `acceptChannelName`. Legacy slot (§5.1): Android
`legacyName` column (migration 10 → 11), web `legacyName` in `ContactStore`.
Placeholders (§5.4): iOS `DisplayNames.isPlaceholder(_:ownHash:)`, Android
`NamesMigration.placeholderSql` / `chatNamePlaceholderSql`, web
`isPlaceholderName` / `isOwnHashPrefill`. NSE: `chat_names.json` entries
carry the slot and `messageNameAt` (`DisplayNames.SharedName`), channel names
their post time (`SharedChannelName`). Web names for non-contacts: hidden
`nameOnly` rows, invites gated by `ContactStore.mayInvite`.

**Retichat-ios (app).** Pure rules in `DisplayNames` (`Retichat/Bridge/LxmfFields.swift`,
compiled into the app and the NSE; tests `tests/DisplayNamesTests.swift`).
- Resolver: `DisplayNames.contactLabel` / `contactName` / `shortHash`, used
  through `ChatRepository.contactDisplayName(for:)` and `resolvedName`;
  channels `DisplayNames.channelLabel` via `RfedChannelClient.senderLabel`.
  System messages keep the hash and are named by `DisplayNames.systemText`.
- Accept (§5.2): `DisplayNames.acceptMessageName`, applied by
  `ChatRepository.applyMessageName` from `handleIncomingMessage` (router path:
  DMs after `allowlistDecision`, group traffic after `groupMessagePolicy`),
  `importNSEMessages` and `handleDistroMessage` (`DisplayNames.distroReason`).
  Announces: `handleAnnounce` and `refreshAnnounceNameFromCache`
  (`DisplayNames.announceNameFromCache`). Channels:
  `RfedChannelClient.noteSender` into `ChannelSenderEntity`.
- Channel send rule: `RfedChannelClient.channelPostName(for:)` →
  `DisplayNames.channelPostName`; recorded by `recordPostName` in
  `ChannelEntity.nameLastDigestHex` / `nameLastIncludedAt`.
- Settings: `SettingsView.displayNamesSection`, saved cleaned by
  `SettingsViewModel.apply` (`LxmfClient.cleanDisplayName`), applied by
  `ChatRepository.applyDisplayNames` (router setters; the announce name is
  also mirrored to the App Group for the NSE).
- Migration: settings `UserPreferences.migrateDisplayName`; contacts
  `ChatRepository.migrateLegacyContactNamesIfNeeded` →
  `DisplayNames.migrateLegacyName` (flag `contact_names_migrated_v1`).
- Retichat field (§10), in `LxmfFields.swift`: `RetichatField` (`field`,
  `displayNameKey`, `maxKey`, `groupEntriesInRetichatField`); `GroupEntry`
  (keys 1–9, `legacyField`, `isBool`) and `GroupValue`.
  - Reader: `LxmfFieldsDecoder.decode` keeps the first value of each entry in
    both forms. `resolveGroupEntries` then picks per entry: the map's value if
    it has the right type, else the old field's. The result is in
    `LxmfFields.groupEntries`, and the typed `group*` fields are read from it.
    It is used by `ChatRepository.handleIncomingMessage`, `importNSEMessages`
    and the NSE's `nseHandOffForm`.
  - Swift never reads key 0: the name comes only from
    `lxmf_display_name_decode`.
  - Writer: `GroupFieldWrite.of` (the pure part) and
    `LxmfClient.messageSetGroupEntry`, the only group writer (all
    `GroupChatManager` sends). It calls `messageAddField[Bool]` or
    `messageSetRetichatString` / `Bool`.
  - Tests: `tests/RetichatFieldTests.swift`.

**Retichat-ios (NSE).** Stores nothing itself: it keeps each delivery's
`unverifiedReason` so the app's `importNSEMessages` applies §5.2. Titles:
`DisplayNames.notificationName` (the app's resolved name from
`chat_names.json`, then the accepted 0xD1, then the recalled announce name,
then the short hash); channels `DisplayNames.channelLabel` +
`channelNotificationTitle`. Sets the Announce Display Name from
`PendingNotification.readAnnounceDisplayName` after its stack starts. No
channel send rule (it never posts).

**Retichat-android.** Pure rules in `names/DisplayNames.kt` (tests
`names/DisplayNamesTest`).
- Resolver: `names/NameBook` (`contact`, `member`, `channelPost`) over
  `DisplayNames.contact` / `channelPost`, built by `ChatRepository.nameBookOf`.
- Accept (§5.2): `DisplayNames.acceptMessageName`, applied by
  `ChatRepository.acceptMessageName` from `onMessageReceived` (after
  `DeliveryPolicy`) and `onDistroMessageReceived` (`Signature.reason`).
  Announces: `onAnnounceReceived` → `DisplayNames.acceptAnnounceName`.
  Channels: `RfedChannelClient.recordChannelSender` →
  `DisplayNames.acceptChannelName` (table `channel_senders`).
- §7 privacy filter: `data/repository/DeliveryPolicy` (iOS's
  `allowlistDecision` and `groupMessagePolicy`); the router's own filter is
  turned off in `ChatRepository.primeCoreDeliveryPrivacy`.
- Channel send rule: `RfedChannelClient.channelPostName` →
  `DisplayNames.channelPostName`; recorded by `recordPostName` in
  `channel_name_state`.
- Settings: `SettingsScreen.ProfileCard` / `DisplayNameField`, saved and
  applied by `service/DisplayNameSettings.save` (router setters; the distro
  announce is republished).
- Migration: settings `UserPreferences.getMessageDisplayName` /
  `migratedMessageName`; database 10 → 11 `data/db/NamesMigration`.
- Retichat field (§10), in `bridge/LxmfFields.kt`: `FIELD_RETICHAT`,
  `RF_DISPLAY_NAME`..`RF_GROUP_MEMBER_KEYS`,
  `GROUP_ENTRIES_IN_RETICHAT_FIELD`, and the `GroupEntry` enum (key, old
  field, type).
  - Reader: `LxmfFields.group(entry)` / `groupBool(entry)`. Per entry, the
    map's value wins if it has the right type, else the old field's. Only
    integer keys in 0..`Int.MAX_VALUE` count. They are used by
    `ChatRepository.onMessageReceived` and `handleGroupMessage`.
  - Kotlin never reads key 0: the name comes only from
    `nativeDisplayNameDecode`.
  - Writer: `service/GroupFields.set`, the only group writer
    (`GroupChatManager`, and the `ChatRepository` group send and leave). Its
    `Sink` lets tests record the calls. It writes through
    `RetichatBridge.messageAddField*` or `messageSetRetichatString` / `Bool`.
  - Tests: `bridge/RetichatFieldVectorsTest`, `service/GroupFieldsWiringTest`.

**Retichat-js.** Pure rules in `lib/display_name.js`, persistent state in
`lib/name_ledger.js` (tests `display_names.test.mjs`,
`display_names_wiring.test.mjs`, `lxmf_signature.test.mjs`).
- Clean and decode (§3): `clean`, `cleanAnnounce`, `decodePayload` (reads
  key 0 of the 0xD1 map from the raw payload bytes; a non-map 0xD1 gives no
  name), `decodeField` (maps this client built), `announceNameFromAppData`;
  run against the shared vectors. `applyToFields` writes or removes key 0
  only (ledger, group envelope, `channelLxmPack`). `LXMF.FIELD_RETICHAT`
  replaces `FIELD_DISPLAY_NAME`.
- Retichat field (§10), in `lib/retichat_field.js`: `FIELD_RETICHAT`,
  `RF_*`, `GROUP_ENTRIES_IN_RETICHAT_FIELD`, `GROUP_ENTRIES`, `keyIs`
  (msgpackr's BigInt too), `readEntry`, `setEntry` / `removeEntry`.
  - Reader: `readGroupEntry`, used by `LXMessage.extractGroupFields`, the
    only group reader.
  - Writer: `setGroupEntryAs` / `setGroupEntry`, and `applyGroupFields`,
    which `_sendGroupEnvelope` calls for every group send.
  - Tests: `retichat_field.test.mjs`.
- §7 signatures: `LXMessage.verify` / `signedPayload`
  (`lib/rns/lxmf/lxmf_message.js`), giving `signatureState` validated /
  unknown / invalid.
- Resolver: `contactName` / `channelPosterName` / `shortHash`, through
  `ContactStore.name` and `channelSenderLabel` in `app.js`.
- Accept (§5.2): `acceptMessageName` via `ContactStore.acceptMessageName` in
  the router's message handler (direct, opportunistic, link, group),
  `_fetchPropagatedMessages` and `_handleDistroBlob`. Announces:
  `ContactStore.updateFromAnnounce`. Channels: `ChannelSenderNames.apply`.
- Message ledger (§4.1, the web client has no Rust router):
  `NameLedger` + `decide`, decided once per DM in `_dispatchMessage`
  (`_decideMessageName`) and per group member in `_sendGroupEnvelope`;
  recorded on a direct delivery proof only (`_recordNameDelivered`,
  `NameLedger.recordDelivered`).
- Channel codec and send rule: `channelLxmPack` / `channelLxmUnpack`
  (`lib/rns/rfed_channel.js`, with the key binding); `ChannelPostNames`
  `decide` / `noteSender` / `recordIncluded` → `decideChannelPost`.
- Announce (§2.2): `LXMRouter.setAnnounceName` / `announceAppData`
  (`lib/rns/lxmf/lxmf_router.js`); distro `_publishDistroAnnounce`.
- Settings: `OwnNames` and the "Names" section of the settings sheet.
- Migration: `migrateContact` (in `ContactStore.init`),
  `migrateOwnDisplayName` / `OwnNames.finishMigration`,
  `GroupMsgStore.migrateLegacyNotices`.

### Python reference

`LXMF-master` (local modification, not in git): `LXMF.FIELD_RETICHAT` (0xD1),
the key constants `RF_*`, `GROUP_ENTRIES_IN_RETICHAT_FIELD` and helpers that
mirror `retichat_field` (`retichat_map`, `retichat_entry`,
`group_entry_from_fields`, `set_retichat_entry`, `remove_retichat_entry`,
`set_group_entry`); `clean_display_name` / `clean_announce_name`, a mirror of
§3 run against the shared vectors; `display_name_from_fields` (key 0 of the
map, bin or str, raw: no cleaning, no signature rules);
`LXMRouter.register_delivery_identity(..., announce_name=None)` and
`get_announce_app_data` announce only the cleaned `announce_name`
("Anonymous Peer" as nil); `handle_outbound` calls
`apply_message_display_name`, which removes key 0 and then, when a name is
set, writes the cleaned Message Display Name as bin in key 0 on every message,
in the same order as `NameLedger::prepare_outbound` so the packed fields match
byte for byte (no ledger, so an unset name sends nothing rather than a clear).
`lxmd` has no default `display_name`, and treats the old template's
"Anonymous Peer" as unset. Tests: `LXMF-master/tests/test_display_names.py`
(it also runs both vectors files).

## 10. The Retichat field: all keys, and the group transition

Agreed 2026-09-27 (James): Retichat takes one field number instead of ten.
Before this, groups used nine top-level fields `0xA0`–`0xA8`. Field numbers
above `0x7F` cost two bytes each in msgpack while keys 0–127 inside a map cost
one, so the map costs three bytes (field number plus header) and saves one per
entry: it is no larger from three entries up.

| Key | Name | Value | Was |
|---|---|---|---|
| 0 | `RF_DISPLAY_NAME` | bin or str, section 2.1 | (new) |
| 1 | `RF_GROUP_ID` | str: 32-hex group id | `0xA0` |
| 2 | `RF_GROUP_MEMBERS` | str: comma-separated hex hashes of all members (invite only) | `0xA1` |
| 3 | `RF_GROUP_NAME` | str: group name | `0xA2` |
| 4 | `RF_GROUP_ACTION` | str: `invite`, `accept`, `leave`, `relay_req`, `relay_done` | `0xA3` |
| 5 | `RF_GROUP_SENDER` | str: original sender hex | `0xA4` |
| 6 | `RF_GROUP_RELAY_SEEN` | str: comma-separated hashes already delivered to | `0xA5` |
| 7 | `RF_GROUP_RELAY_FOR` | str: hash of the member being relayed for | `0xA6` |
| 8 | `RF_GROUP_RELAY_DONE` | bool: relay-complete signal | `0xA7` |
| 9 | `RF_GROUP_MEMBER_KEYS` | str: one `hash:base64-public-key` pair per invite chunk | `0xA8` |

Each value keeps exactly the type it had as a top-level field, so the group
logic itself is unchanged. Group semantics are RFed-spec `Group.md`.

**Transition (group entries only; the name was never sent anywhere else):**

- **Readers, now:** take each group entry from the Retichat field when present
  there, otherwise from its old top-level field. A message may carry either
  form.
- **Senders, now:** keep writing group entries to `0xA0`–`0xA8`, because
  released apps read only those. One constant per client selects the form:
  `GROUP_ENTRIES_IN_RETICHAT_FIELD = false` (Rust/Kotlin/JS; the Swift
  equivalent `groupEntriesInRetichatField`). Both forms are tested.
- **The switch, around 2026-10-26**, together with the proof re-enable
  (`DELIVERY_PACKET_PROOF = Required`), once most devices run a build that
  reads both: set the constant to `true` in every client. Group entries then
  go only into the Retichat field and `0xA0`–`0xA8` are free again. Readers keep
  accepting the old numbers until a later release removes them.

Released builds from before this change skip an unknown map at `0xD1` (the iOS
decoder's `skipValue` handles maps; Android's decoder reads nested maps), so
the name entry is harmless to them.
