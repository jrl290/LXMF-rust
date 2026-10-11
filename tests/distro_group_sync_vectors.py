"""Writes tests/distro_group_sync_vectors.json: the golden vectors of the
group sync G (RFed-rust SPEC.md §17.14, GROUPS-DISTRO-DESIGN.md §7, §10, §11.1,
§17.1, §19.1), made with the Python reference (RNS 1.5.2, LXMF 1.1.1, RNS's
vendored umsgpack), so that LXMF-rust (tests/distro_group_sync_vectors.rs),
both phone bridges (Retichat-ios rust/retichat-ffi, Retichat-android
rust/retichat-jni, each with a copy in tests/data) and Retichat-js assert the
same bytes and the same reading against an implementation that is not their
own.

Run from anywhere with the workspace venv:

    /Users/james/Offline/Reticulum/.venv/bin/python -I LXMF-rust/tests/distro_group_sync_vectors.py

The output is the same on every run: every key is fixed, every message is
packed from fixed values, and Ed25519 is deterministic. Only encryption to D is
random (an ephemeral key and an IV), so ENCRYPTED holds the output of one RNS
Identity.encrypt per sealed message, made once with --new-sealed (which prints
one for each sealed message ENCRYPTED does not hold yet, never the others) and
fixed here. The script checks that each decrypts to its packed message before
using it. Do not replace them: every pinned value that follows from them would
move.

The script also reads every vector back with its own reading of §11.1 rule 4
(read_group_sync below, a second implementation of the rule) and stops when a
vector says something that reading does not.

Repeated keys (RFed SPEC §17.14, James's ruling of 2026-10-11: parity). The
reference refuses an LXMF message whole when its payload holds a map, at any
depth, that repeats a key: RNS's umsgpack raises DuplicateKeyException, so
LXMessage.unpack_from_bytes raises and LXMRouter.lxmf_delivery drops the
message. Every client does the same, on the direct path and on the distro path.
`refused` holds such messages and `key_equality` the pairs of keys umsgpack
takes for one key (or not); the script asserts that the reference refuses each
refused message, and refuses or reads each key_equality message as it says. No
other vector repeats a key, which the script also asserts.

Unhashable keys (RFed SPEC §17.14, decided 2026-10-11: parity). umsgpack
refuses a map used as a key, and an array key that holds a map at any depth
(it turns the array into a tuple, which Python cannot hash then), with
UnhashableKeyException, in any map at any depth; LXMF.py drops the message
whole. Those messages are `refused` too, each with the `reason` the reference
gives: the first refusal in the order umsgpack reads the bytes (a key is read
whole before it is judged; an array key's value is read before the key is
hashed). An array key that holds no map is read (`key_equality`).

Nesting (RFed SPEC §17.14, decided 2026-10-11: one limit, Python's measured
delivery-path depth). umsgpack reads a payload recursively, two Python frames
for each level, so a payload nested deep enough raises RecursionError, and
LXMRouter.lxmf_delivery drops the message ("Could not assemble LXMF message
from received data"). Where depends on how many frames sit under the unpack.
Measured with tests/delivery_nesting_probe.py, real LXMF over local TCP
between three processes (CPython 3.13.5, RNS 1.5.2, LXMF 1.1.1, recursion
limit 1000), 2026-10-11:
- propagated (propagation node -> message_get_response -> lxmf_propagation ->
  lxmf_delivery), the unpack the 10th frame of its thread: a field reads 492
  nested arrays or maps whose innermost is empty and 491 whose innermost holds
  anything (a nil, an int, a str, a bin), and refuses one more. That is exactly
  "no value deeper than 493", the payload at depth 0, its fields map at 1, a
  field's value at 2: the one limit every client follows (NESTING_MAX_DEPTH).
- direct over a link as a Resource (assemble -> delivery_resource_concluded ->
  lxmf_delivery), the 7th frame: 494, 493 or 492 by what the innermost holds.
The script checks every `nesting` vector on DELIVERY_FRAMES, the propagated
path's measured stack, rebuilt in a fresh thread (on_delivery_stack), and
asserts the reference's verdict for each.
"""

import base64
import hashlib
import json
import os
import sys
import threading
import unicodedata

import RNS
import RNS.vendor.umsgpack as msgpack
from LXMF.LXMessage import LXMessage

# D's private key: X25519 private key (32) | Ed25519 seed (32), as
# distro_sync_vectors.py.
D_PRIVATE_KEY = bytes(range(64))
# M, a member who sends to D; X, a key that is not M's (a forger).
M_PRIVATE_KEY = bytes(range(64, 128))
X_PRIVATE_KEY = bytes(range(128, 192))

# The sending device's own lxmf.delivery address (fields[0xFD]).
DEVICE = "0123456789abcdef0123456789abcdef"

GROUP_ID = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
GROUP_NAME = "Hike — Sunday"
# A listed member whose key no device holds.
OTHER_MEMBER = "e1" * 16
POST_TEXT = "See you at 9 — bring water ☀"

FIELD_TICKET = 0x0C
FIELD_CUSTOM_TYPE = 0xFB
FIELD_CUSTOM_DATA = 0xFC
FIELD_CUSTOM_META = 0xFD
FIELD_RETICHAT = 0xD1
DISTRO_GROUP_TYPE = "rfed.distro.group"
DISTRO_MARKERS = ["rfed.distro.transfer", "rfed.distro.sent", "rfed.distro.channel", "rfed.distro.group"]
MAX_AT_MS = 2**53 - 1
LEFT_MAX = 32

# Nesting (RFed SPEC §17.14): no value of a payload deeper than this, the
# payload at depth 0, the fields map at 1, a field's value at 2; so a field
# holds at most NESTING_MAX_DEPTH - 1 nested arrays or maps, the innermost
# empty. Python's propagated delivery path, measured (see the module text).
NESTING_MAX_DEPTH = 493
# The frames of the thread that unpacks a propagated message, the unpack's
# own included: _bootstrap, _bootstrap_inner, run, job (RNS Link's response
# thread), handle_response, response_received, message_get_response,
# lxmf_propagation, lxmf_delivery, unpack_from_bytes. Measured by
# tests/delivery_nesting_probe.py.
DELIVERY_FRAMES = 10

OPS = {
    # op: (LXMF timestamp, at_ms)
    "create": (1790000000.125, 1790000000123),
    "accept": (1790000100.5, 1790000100456),
    "leave": (1790000200.75, 1790000200789),
    "post": (1790000300.25, 1790000300000),
}

# 32 distinct group ids for a full `left`, none of them GROUP_ID.
LEFT_FULL = [hashlib.sha256(b"distro group sync left %d" % i).hexdigest()[:32] for i in range(LEFT_MAX)]

# What the invite parser trims from each entry: Unicode Zs (space separators)
# and U+0009, exactly the set Swift's CharacterSet.whitespaces is, and the one
# every client's own trim includes (Kotlin trim(), Rust char::is_whitespace,
# JavaScript trim(), Python str.strip() each take more, and not the same more).
# main() checks it against this Python's Unicode database.
INVITE_SPACE = "\t \u00a0\u1680" + "".join(chr(c) for c in range(0x2000, 0x200B)) + "\u202f\u205f\u3000"

# A placeholder at_ms whose uint 64 bytes occur once, replaced by the encoding
# under test (umsgpack, like rmpv, writes a non-negative int in its shortest
# unsigned form only).
PLACEHOLDER = 0x1122334455667788

# One RNS Identity.encrypt of packed[16:] to D for each sealed message, made
# with --new-sealed.
ENCRYPTED = {
    "g_accept_full_left": (
        "a27b7a85c416a5c5064e7e1f69bbfe2a6708805b597aed429231dfdcc32b0c3f"
        "7b26c5f2f06529e1c67ff2ae6953645ff41c3a7421f5735d66d08b334bc7e4ec"
        "aca045c9c46405847b60c626490b2d70261c39f3a88768f059fe119d1d3958bc"
        "f16439eb29c5bbbaf7e5a969c2ea63956a29a6c81cb3b4cbfc3c0ab062c3d74a"
        "625502b4bbf43c32d959761bd37533406310793ca14c5f1995e3ce77f8ba3012"
        "eeb79e4127b58765777293d6b8ca77f10fe330a83c05313c7cff769cfaf94a51"
        "7a606106346942c0db35f8f69025d707ae65bbb2e1ba7e53ccc86b2d89410c5e"
        "bcbc1033c775ca89cc6b4a46949e93efdd779a8a012c5e949db7763800461011"
        "d052aa3adf29f1db7d5f6f4d606db24033055aef47e3dcb144ed92561c106537"
        "a71b8656b1fc66a1d2333a11de8f5d2d7aba9c1e61d81dca6137920a77925116"
        "7b397067dc041da077921369df940a1978b6b0cd32f73c51832ea7ff4cb3394b"
        "aed849fff97f62441182524b364afa44c4d4734edb3cb1bb16a93d1d73a0a20c"
        "17940cf1bb9af77b7898df562914d5f38c2906168e1d3455ef9ed3e02c392724"
        "003382e7a01df39db702750d69efac6a171bbe89751a7cad5fbb53f7e1359621"
        "3576f371ea198d511ad7066481487577043a8ede7136d4adf95d777e66bc6dc3"
        "a1385d6f24d39f498b803ad55780d5580d8aa4a8ef17a7c6f1988ce2ac38a61e"
        "ac684965a2928a2d3814a8cb64dea2532d12a89801fd5c7b58160632f43b11b6"
        "0f2198f35b8226426788d1cf101ec4c728b4c13060f64cbf6c564d79cd388f93"
        "dfd63c1aa67ec3b6cea58e84f945aa3168f74fb31bfe5e0e0b04d2b28de7540e"
        "16f560ff33f48d00579e57f1d12139138348c2a52f4db7f8150e384305c13b87"
        "22eab6485502d8200a5c96d51b0bbaa902f0c20fc3661918e52d38c23c4936aa"
        "136838644f25fd824d79c5e7cc089ec8573f88d94add75fa3cf57d4d8f85ab1a"
        "bdb973accf47d56a5f8ac2aa603561c3c9aa00e4f6c4b1a135205acaa32d8423"
        "fa60eef0c61439461338271c6d8271221642321e63fd997ffdaad6b11141bfb1"
        "fe744741ac50a311e703c415331cfa7dfd63945ad6521cdf1a59d2b09ebb0f08"
        "afad1a0b47a3e0d505751320757e154a283c9353ae52d1a09bccb8c3eb711df4"
        "1f3285395aca9f4a3bb45c8a390d981904e23e14054e63c30e6cfd8b5b2e60fe"
        "5395efae1ec002c63b44c14feac940af818dcc05b184fb3eaa169051aa08a8ce"
        "5357c0fb7faceba5f60d1873125b6b2a137c6daca1f1af58601894850e3a5631"
        "2bd4d962ad28930cd1e2d6b9517cc28f7cad945ea31e80d90af17de40e9be003"
        "10fd151d6cfbba880c8cb9cf86f58b6a71f9946b031b0a24dc5e39b5cd85de47"
        "6d812731f0d9dfd028b12bad99667fa02aaed5c990e15cf2791884c43d7a573c"
        "2956055de5d9c3909142a917af7e2ff6c24ebd73d8e4890e3d61fdbe59db957c"
        "adf8301a45e3bfc81aafe9fb50ffbc46667a857d67a3561afe73584b7359cddd"
        "be33559d70c68092a4aa87823bf80b819d930298a9a6983c821ee8a8e60de347"
        "f0e13d05de4c6b83bf9231606d0c7c55690aebcbb976a13ed10bbdbea6bd7391"
        "aad5f43f59e8ffa329d6df65378d14159a9b88d907cb8ab2d54043d85471c004"
        "4a0d6613ecb9d38d3da1e8eb1caa470845ba2ffb2eda74f6a01eb55229ced265"
        "f21d4a92267de7a878d469d17f7a40d96062f21ac1861acf2cde8523d1cce3b0"
        "7d52ab0754ad9dc597a4e688badf288f6c712b52f897a69ac566b79efe74bdd0"
        "245937eaca1d119f5983ae1748fcbab74866a09e8d5ed9c5b86da9fe8728838f"
        "c846cdd03a5df59385f66000abbf12b6affa0f7ea7475290bfb163418e0ae576"
        "15e0ba96c29aaede0e2b96804bb478dbfa200adde347c1ccaba388cd47bcda4c"
        "d3666e0c0d491864f7921732b53d459f39d36c0acc905c9e2c26c716413223a2"
        "9e1f81b24ea737a8b4c648fe06cd99349d168f29721352c7f71182ee45f9e373"
        "574789f5deecceaa0ba02a1d2963713dbe5a7bb86e458768277c3750f2a7c9b7"
        "65606576bc56bcf02268b761fddac48f900e2236fc6114e8845f1e4b02cc61f9"
        "38fb6fafcd9bdff2b3476b8787da3155debe271234ea110bb90cffa167ec34d9"
        "d40ab47cec6b275ca55dbad45b379cc3b6126d78baa34adc775e3776090d6219"
        "61e7bae00638c0177267747b46de47a7178a32330ab6b277e82e811f70d0e70e"
        "2fa9516f7dfabe5c38d3b91c1507d33bff883094c79f3ae47ce23cd537752f2a"
        "2de851dccd0c74ef22a261b7f7c0f0a1fe43ca16f2f848259c0afdd105ce3071"
        "e2f4fa8fa83c9ef521a36879964c88837601f820a7d9c1809ab64010f2ac2924"
        "e96b5bed2353543d1a8fea753550caac0926793d696b0dcf597b4640a7bdafee"
        "7d85588d608b9feb97936c72ef14fac4937c6a4700549185086efee71a263af2"
        "7967acd6e5fac8f15c82aaad0da5ee2f"
    ),
    "member_accept_legacy": (
        "065de13e9c4d668c9171febd73a477621d923e3a4021b78042c170bd779b1d79"
        "2cb9957626f2e569a2ff810fcfea8a6b6ea243ec640f8ad6fabfaee968ef804e"
        "25bc9ee0d7e38d9b34ce9de21a911a4158b01e35507a8419712221506e89c2a6"
        "7d67ad6cfdb85457f25aae1272af8c51329e2bb67a9294b35f895ab842886206"
        "5589dd75bbaae4942d843535d3d1974c380160ea7b06d773f5eef2b671fdb23d"
        "9c5eb448c5a8d6b19e366449685195ec2af8497963af618af8a526f96b962bc5"
        "77b1a31de0cecbc0609c213b6193b2ba71e8d0c2a318bd83e9bb4bfceea87e34"
        "6aea07f5b5d8472721edd97b8eca1792fa6defa47f41fd3bcdffb678156134a9"
        "b37229d566876ef958b8080b5c37986deb609d324badcc3bf5c55de6b4913593"
        "765054cda0152495852205ba34e3a2846d57841d64a919540e37992c8e6290e4"
        "43971678ace31bbf7f91f5dbf04e4f0ec16905529505f0a26ccfb6e0bd23c9d9"
        "77606868558642ea36455fe6fc10e7d114b3994441ca3810f5b884bb9b6e667f"
    ),
    "member_accept_forged": (
        "7cba904ba299518cd8a41e620b8ae45bac57e85f1b60d380f205fd36a2c7fe12"
        "0e20a011f2f7b665b3354ae712b0975859b8b762d51e37caeba13dcd4f210ef2"
        "45b9e18f8bf1eefd68825a1c8152e54527767a0a772b52e770c7ce1281f326c0"
        "29950e266508ffdc2b8ecfca722f214f43c5773c0886283e72fd6c9a1c86fdef"
        "c7d9cd6f4edefbb1f103ad3bbf1694337a71971f4422b5f27563f2b74ec90d2b"
        "bd9bebae44e5c36d367a4b4280bc2dde89a0546814d6106796b89fa6b8a79502"
        "089ec84891e00e1791fb0b277a5e7d437ac1253d5cf5930e9ca72c96cd4652d5"
        "bbb4d63364713e598fd17bde79b4837078f069baa081bd53611637ad69fdd4e2"
        "621b7f28148ce64e1839ecdd8a07a023efcb9bd32c43f649d3a597d21eb59776"
        "951312f7f1bb35a1fc97342df832c93f52eed931f96395b7546e60b13945d2ef"
        "a44c900e462d08331032ddda7a7e7f33aa47a295886624c3b5b77878139f1af0"
        "99a1a2a0ccf129e880b0832969cea9efcf80ea4ea330a47d7aed4a4b1cc51970"
    ),
    "member_invite_retichat_field": (
        "2473f94804ee4d5bc9c9afcef0bae1010901bbbc14d2181a222472cbfd02e927"
        "0e347f6911256b77b4764766062aaa70ba0133b2f7e3d23c748597e36357e2b4"
        "a0a9aae8669c726250c09e1b09e77fe458a6282ddd385f0eb4ad6220b89051f9"
        "302c25485e8a2cbb245e161ac2f200c84409b3d81744416330635b5bc7a2bf11"
        "154b74dceba91b978266a5a1f893e09c80959417c7895e134a3031494585f968"
        "98e66a83f8f7ac3fc3f2b9aca28e129d919c0a97fef7a234fca397e46e60f1f0"
        "c36f349147cd0c01de75dcefe71d92304c5f12a545ec580c4aeee4ae8fc1193f"
        "df62ad76bba4d88b500e24a3e0a887a23090685f8539a321aa7d5e2c9012a31e"
        "3688c5de860afc29b7423c8dcf785c8522e06a45f2886445c6e35892d99b2468"
        "4f067c1b1c447e878b28599118e21a687bc045d6226f3dd87be119e2abebe2cd"
        "2632b41282917d741b4abc98826d952307f793fe4457a78d91c1dd6a05088957"
        "e2bbb3921e5ef983a2f49bbdd2569b62fecbc935667ee7abb388ab94f94a14f9"
        "e886fafef4d220a08117c291e12f674b5a0a65af65a461910d90ad46831269a5"
        "19ed3714f3ef465a7c7c83a5f82a3241a9d39aff196bcc1bfa33e9321cf0cb41"
        "d3eab699e11fd1f50a356cdb2790b6605fde5eae35c4ba12c3c07eee93e4b57e"
        "c1c76836c48440e285454af51ed6869b1cb0d3cbe2a52a07b2bc5c62b88cffa4"
    ),
    "g_accept_web_form_int64_at_ms": (
        "7b9a5728a01dfa62d9b1686de6020e58186ef3c792deb8d211b2404bb2bf6330"
        "71c6b07277e61eeaff630f01d96882ff7071f608be92aa0fac82681e3f341a1d"
        "39a22a42a1bcfca4be11273b4c98a348ab536199fcda554015e05c24d6bb2930"
        "b50fbb34139f5d1956af838a70da1bdb93d73cedbca8933d695ee5e0479614cb"
        "8d4573526b594d34b86b2469a8fe324213901fa6c339c7975592b77d5600050a"
        "8328e6087cd3629d2449dae7ad3ba57e85b0da3fbf4eb7a148e12fcd8ad5bcfe"
        "b941e99e75f674bbe88836634d6747a41d8b87246fc69aa372ea9c24a9a78b12"
        "9fcbaa5f321c3c1a167deb303fae6bad79c3c918cfcd8a46ad57daf5471e50f6"
        "11dc151db5508cd5de1dfbe29928885908a32585379cd1d791765c359842be01"
        "232b07d38dd72120d6a12c0c37acda6db77ae613c7a709f63088a53b37241bf9"
        "f6ed4fdfac159b89911c3fa6f523e2b82e50df207a9da70db858441aed3d1c71"
        "e167051a8acb71fc739e9b08ae75ea926ee93c089213c04b125e6bf79ccff0ca"
        "17b1dd05d56e393a24f2d93fe50459e5c9fb9fbb5f4a29c69a066e1c8cda8a06"
        "c7234fe4d6b6407bb74a9a468c719cb10110b65296622a308da5ba126362ba24"
        "5b815283dacc36bc7667a838d91b33a815d494d99bb8de47095200dafd5f6b8c"
        "c3d40e40ccf0e79196f04665cf2df70d14f9e92cb7f5dd0792db104bf90892d8"
        "108c408023fc072ff618ba4e6656070218c5fad12d2f173f6be9a20dcd551416"
        "4976307d1c20ca12f2ab661c98d26a19c4aa9053a1c42eaec6e3856802f8fef4"
        "d5c37ecb7ed9f397160e567f3b0ed75379e2cf744e1992c2a2304ee585bb3a48"
        "875ebc8da7f8359947bbf008f1cf3c940a279bdf07a547d4ea32b9ffbb696e11"
        "99443f1dfbc966984e817ec52e8f8b89adc85c815f19acc89bef8faac01d6d94"
        "8268db11715172f3181ad705a83214ce6c2dd871b10f2cc33fa100cdc072eb3b"
        "3a83a19865fdb59ce5b04da8356cb019675cffa2c3887705dac3c191f79ff848"
        "619a257fde548ef14639c57ec604b32ceda41a7687fae7e2b9d2df2e9f446c61"
        "d173750efc36b0c763fce7ba85da99baaf52d5b8b75ea41facd7dba346fde166"
        "1b74029120dbefde340ac67f23c3d8a692270d0693f9b75a6603e9d750b1578e"
        "c70e6923fe1a99c0ec997d9cd6a37de993664aebf165aab79010df87e203fc0d"
        "4d3d6cf020805dc27a919baea78d2d7017151272c5e31b80ad09168b9d5b5b53"
        "ff3b254bf6d2907f91e068191fdc25aaaddb8bbed877a34a60751bcab6d32b3e"
        "244f31315ea0441dd516bd1069a0c4b99afa9b8a2623fedcad396c8a1414c575"
        "ca0559a487f9fbb71f5d7b344e781dec68ac560df538c49d878e7426aa9a1b02"
        "f33f4bfe8266a712bde1418c89125a60d959b6c91065479898b6f2132be5a051"
        "e6f759ef5a62bf8e4dce81f9d27f9908329658c7c51913e883c09caa380a6f3d"
        "a18fc451344104e85013d8af7828a62ffe3f0d260609ed13eb748b4e9237332e"
        "aadc0d764a85391ddbbbfdd30317adb1482fd7e10f36bb3510dda66b1c92c054"
        "c927e15690045b420d1baeb52436b4322b0084cc479b3812de23f46b6a399024"
        "d4ddfe0201f9c8dc8a9cf31c1fa1557458553e9563842afa157cd62ec6c151a0"
        "ffa8445a45384d00b72637408f1f59632a11f42950782c6b68ae098adac72662"
        "c3c928e5a483c365bdbcc39b828d0ad457614af73495a25969d62689f27d0cd9"
        "ca9704cea4ec26ab7b2d8c61cacd30ce0f91249f919b4815a96c2fb7d71a6ecd"
        "927257c60d0a2096f3befcfd8947a9782f34bc04e0176e6f568f72274d0d0add"
        "02e0d6da4123c75df893d335ba4f7708648c8c116113bebb48bcd14c4a3d4f05"
        "35e65a95331f8a60bd2bd36b44ef75411fea038b8d48357c71fe3da1c354a1c8"
        "10ab4a20dca67425f14f9081d7db0a28e06585b6d341be48363ef66865cac06f"
        "ab37848b407e38192b9fa80c4c084297401e5f9f6eb616bed04cccc9ef1a6946"
        "c67f9eb9b850d1687e947681f692a7a2755b08c94fab151d8dd1a7854423d303"
        "7dca2bc8921f0a163b7ed1d2420a50164abd8a9d14fd8b07879668949b87c34f"
        "e2ed5fd61f369bdcca798860bed7b7ac13254e6c53a793bf47c3c78238b57252"
        "7a80a389de09133e7479395a0ec721cb8daf7e09a9f5f745c760c48237b293d7"
        "15a52d1faa7cfe3560a41f5963fdd2d0f6be3b08c435b7e95b1dd8e202f63685"
        "c3af84ef6fa76769ec0b9a14022b5df4170b92d3269f9b6d6d3fb68458bb59ea"
        "07676d44219e62edb06a1ac46fad0ec1ecc422651cca30ae0d31d587bf777c50"
        "5380a7a30173586c3894b7c2fef34a2105477d8fbe2f13e5402c8256e14bd184"
        "3921b61c789deaec5977d3677d1c0ce6d5b62168167480d1062a314c69336ed2"
        "f0b1893370594b6ddc65a43b10f72b9e7449a782f591923c06e458aa1651061b"
        "268f7400ad4d24aa3342f11883eeace9"
    ),
    "member_post_legacy": (
        "f6b72d4f3135509362baf466de272da47ce9eef6d4398e1f0ecd1513dec35b23"
        "f45d58b8df746a4c5e76573fe4bb172b77ae4300cd15eea060fe1e524987a19c"
        "95c42204716ca217e6b9a3047310f5a9cfa4508620e3be6872b3e0969783d4a3"
        "9ff13dc22a55a0ae971c17b9203b9beb71275e7cb851f8933fdab68ea2a9eedc"
        "161b067b4a1c2cfc6abb796d7cb33c5de13472e5fad2e9dc161cb566767f243a"
        "ea5e3537765d16c455aaeafdc312b3df07a6c53db936b0eb856d2aadb53069c7"
        "f6e47ec915093843677a8bfd2f264f7c81ba69e331fdfe4b3df951a2677cf3d0"
        "c461438b8a065beaf0b6d05f020d4484b9b9ff8efe3ed005ec1707e6beb23e53"
        "bd2d8f95093f2e9fc306c4b481be4ad4"
    ),
}


def hexs(b):
    return b.hex()


def key_entry(identity, delivery_hex):
    return f"{delivery_hex}:{base64.b64encode(identity.get_public_key()).decode()}"


class Raw(bytes):
    """Msgpack bytes already packed, written as they are by raw_map."""


def raw_map(pairs):
    """The msgpack map of `pairs` in their order, a key repeated as often as
    it is given (a dict holds each key once): a fixmap header, then each key
    and value as umsgpack packs it, or as given when Raw (a key too: a map or
    an array that holds a map, which no dict can have as a key)."""
    assert len(pairs) < 16
    def packed(x):
        return x if isinstance(x, Raw) else msgpack.packb(x)
    return Raw(bytes([0x80 | len(pairs)]) + b"".join(packed(k) + packed(v) for k, v in pairs))


def nested(levels, innermost=b"\x90", kind="array"):
    """`levels` arrays nested one in the next (a fixarray of one each; maps of
    one entry {0: ...} when kind is "map"), the innermost given as msgpack
    bytes: b"\x90" an empty array, b"\x80" an empty map, or an array or map
    holding one value. Built as bytes: umsgpack's own packer recurses too."""
    assert levels >= 1
    head = b"\x81\x00" if kind == "map" else b"\x91"
    return Raw(head * (levels - 1) + innermost)


def reference_refuses(fields_bytes):
    """Whether the reference refuses these bytes for a key: RNS's umsgpack
    raises DuplicateKeyException on a map, at any depth, that repeats a key,
    and UnhashableKeyException on a map key or an array key that holds a map,
    so LXMF.py (LXMessage.unpack_from_bytes) drops such a message whole. Read
    here on this script's own stack: never used for nesting."""
    try:
        msgpack.unpackb(fields_bytes)
    except (msgpack.DuplicateKeyException, msgpack.UnhashableKeyException):
        return True
    return False


def on_delivery_stack(fn, *args):
    """fn(*args) run as the reference's delivery path runs its unpack: in a
    fresh thread whose frames, fn's own included, are DELIVERY_FRAMES deep
    when fn starts. Returns ("ok", value) or ("raised", exception)."""
    out = {}

    def at(levels_left):
        if levels_left > 0:
            return at(levels_left - 1)
        frame, depth = sys._getframe(), 0
        while frame is not None:
            frame, depth = frame.f_back, depth + 1
        # This frame is one short of DELIVERY_FRAMES; fn's is the last.
        assert depth == DELIVERY_FRAMES - 1, depth
        return fn(*args)

    def run():
        # _bootstrap, _bootstrap_inner and Thread.run are 3 frames; run is the
        # 4th and each `at` one more.
        try:
            out["ok"] = at(DELIVERY_FRAMES - 1 - 4 - 1)
        except BaseException as e:  # noqa: BLE001 (the verdict is the exception)
            out["raised"] = e

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    return ("ok", out["ok"]) if "ok" in out else ("raised", out["raised"])


def reference_verdict(packed):
    """The reference's verdict on a packed message, its own
    LXMessage.unpack_from_bytes on the delivery path's stack: None when it
    reads it, else why it refuses it whole (LXMRouter.lxmf_delivery then drops
    it: "Could not assemble LXMF message from received data"): "repeated_key"
    (DuplicateKeyException), "unhashable_key" (UnhashableKeyException) or
    "too_deep" (RecursionError). Any other exception is an error here."""
    outcome, value = on_delivery_stack(LXMessage.unpack_from_bytes, packed)
    if outcome == "ok":
        return None
    if isinstance(value, msgpack.DuplicateKeyException):
        return "repeated_key"
    if isinstance(value, msgpack.UnhashableKeyException):
        return "unhashable_key"
    if isinstance(value, RecursionError):
        return "too_deep"
    raise value


def reference_refuses_message(packed):
    """Whether the reference refuses the packed message whole (any reason)."""
    return reference_verdict(packed) is not None


# --- A second reading of §11.1 rule 4, to check the vectors against --------

def is_hex32(s):
    return isinstance(s, str) and len(s) == 32 and all(c in "0123456789abcdefABCDEF" for c in s)


def invite_members(csv):
    """The phones' invite parser (iOS/Android DeliveryPolicy.members): split
    on ',', trim INVITE_SPACE (Zs and U+0009) from each end, keep entries of
    exactly 32 lowercase hex, first of each."""
    out = []
    for part in csv.split(","):
        h = part.strip(INVITE_SPACE)
        if len(h) == 32 and all(c in "0123456789abcdef" for c in h) and h not in out:
            out.append(h)
    return out


def read_group_sync(fields, d_hex):
    """None when fields[0xFB] is not the group sync marker; else the §7
    group_sync object (problem set and the rest None when rule 4 fails)."""
    marker = fields.get(FIELD_CUSTOM_TYPE)
    if isinstance(marker, bytes):
        marker = marker.decode("utf-8", "replace")
    if marker != DISTRO_GROUP_TYPE:
        return None
    # by: 0xFD as text when it is a str or a bin, else "" (absent, nil, an
    # int, an array, ...), lowercased.
    by = fields.get(FIELD_CUSTOM_META)
    if isinstance(by, bytes):
        by = by.decode("utf-8", "replace")
    by = by.lower() if isinstance(by, str) else ""
    empty = {k: None for k in ("op", "group_id", "at_ms", "name", "members", "keys", "creator", "text", "left")}

    def bad(why):
        return dict(by=by, problem=why, **empty)

    arr = fields.get(FIELD_CUSTOM_DATA)
    if not isinstance(arr, list):
        return bad("0xFC is not a native array")
    if not arr or not isinstance(arr[0], str):
        return bad("op is not a str")
    op = arr[0]
    need = {"create": 7, "accept": 8, "leave": 4, "post": 5}.get(op)
    if need is None:
        return bad("unknown op")
    if len(arr) < need:
        return bad("too few elements")
    if not is_hex32(arr[1]):
        return bad("group_id")
    at_ms = arr[2]
    if isinstance(at_ms, bool) or not isinstance(at_ms, int) or not (0 <= at_ms <= MAX_AT_MS):
        return bad("at_ms")
    out = dict(by=by, problem=None, **empty)
    out.update(op=op, group_id=arr[1].lower(), at_ms=at_ms)

    def text(v):
        if isinstance(v, bytes):
            return v.decode("utf-8", "replace")
        return v if isinstance(v, str) else None

    if op in ("create", "accept"):
        name, members, keys = arr[3], arr[4], arr[5]
        if text(name) is None:
            return bad("name")
        if not isinstance(members, str) or d_hex not in invite_members(members):
            return bad("members")
        if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            return bad("keys")
        out.update(name=text(name), members=members, keys=keys)
    if op == "accept":
        creator = arr[6]
        if not is_hex32(creator) or creator.lower() not in invite_members(arr[4]) or creator.lower() == d_hex:
            return bad("creator")
        out.update(creator=creator.lower())
    if op == "post":
        if text(arr[3]) is None:
            return bad("text")
        out.update(text=text(arr[3]))
    left = arr[need - 1]
    if not isinstance(left, list) or len(left) > LEFT_MAX or not all(is_hex32(i) for i in left):
        return bad("left")
    out.update(left=[i.lower() for i in left])
    return out


# --- Building G -------------------------------------------------------------

def custom_data(s):
    op = s["op"]
    arr = [op, s["group_id"], s["at_ms"]]
    if op in ("create", "accept"):
        arr += [s["name"], s["members"], s["keys"]]
    if op == "accept":
        arr.append(s["creator"])
    if op == "post":
        arr.append(s["text"])
    arr.append(s["left"])
    return arr


def g_fields(arr, device=DEVICE):
    # The order set_group_sync_fields writes them in.
    return {FIELD_TICKET: b"", FIELD_CUSTOM_TYPE: DISTRO_GROUP_TYPE, FIELD_CUSTOM_DATA: arr, FIELD_CUSTOM_META: device}


def substituted(data, substitute):
    if substitute is None:
        return data
    old, new = substitute
    assert data.count(old) == 1, "the substitution must be unambiguous"
    return data.replace(old, new)


def pack(signer, dest_hash, src_hash, timestamp, title, content, fields, substitute=None):
    """An LXMF message packed as LXMessage.pack packs it: dest | src |
    signature | msgpack [timestamp, title, content, fields], signed over dest |
    src | payload | full_hash(dest | src | payload). Read back with the
    reference's own LXMessage.unpack_from_bytes for its hash."""
    payload = substituted(msgpack.packb([timestamp, title, content, fields]), substitute)
    fields_bytes = substituted(msgpack.packb(fields), substitute)
    assert payload.endswith(fields_bytes)
    hashed_part = dest_hash + src_hash + payload
    message_hash = RNS.Identity.full_hash(hashed_part)
    signature = signer.sign(hashed_part + message_hash)
    packed = dest_hash + src_hash + signature + payload
    assert not reference_refuses(fields_bytes), "only `refused` and `key_equality` repeat a key"
    reference = LXMessage.unpack_from_bytes(packed)
    assert reference.hash == message_hash
    assert reference.fields == msgpack.unpackb(fields_bytes)
    return packed, message_hash, fields_bytes


def pack_raw(signer, dest_hash, src_hash, timestamp, title, content, fields_raw):
    """An LXMF message whose fields are the msgpack bytes `fields_raw` as
    given (a map that may repeat a key, which no dict can hold), packed and
    signed as `pack` does: the payload is a fixarray of 4, then timestamp,
    title and content as umsgpack packs them, then `fields_raw`."""
    payload = b"\x94" + msgpack.packb(timestamp) + msgpack.packb(title) + msgpack.packb(content) + fields_raw
    hashed_part = dest_hash + src_hash + payload
    signature = signer.sign(hashed_part + RNS.Identity.full_hash(hashed_part))
    return dest_hash + src_hash + signature + payload


def main():
    d = RNS.Identity.from_bytes(D_PRIVATE_KEY)
    m = RNS.Identity.from_bytes(M_PRIVATE_KEY)
    x = RNS.Identity.from_bytes(X_PRIVATE_KEY)
    d_hash = RNS.Destination.hash(d, "lxmf", "delivery")
    m_hash = RNS.Destination.hash(m, "lxmf", "delivery")
    x_hash = RNS.Destination.hash(x, "lxmf", "delivery")
    d_hex, m_hex = d_hash.hex(), m_hash.hex()
    assert len({d_hex, m_hex, x_hash.hex(), OTHER_MEMBER, GROUP_ID}) == 5
    zs = {chr(c) for c in range(0x110000) if unicodedata.category(chr(c)) == "Zs"}
    assert set(INVITE_SPACE) == zs | {"\t"} and len(INVITE_SPACE) == len(zs) + 1, "INVITE_SPACE is Zs and U+0009"
    assert GROUP_ID not in LEFT_FULL and len(set(LEFT_FULL)) == LEFT_MAX

    members = f"{d_hex},{m_hex},{OTHER_MEMBER}"
    keys = [key_entry(d, d_hex), key_entry(m, m_hex)]
    assert all(len(k) == 32 + 1 + 88 and k.endswith("==") for k in keys)

    def sync(op, left):
        s = {"op": op, "group_id": GROUP_ID, "at_ms": OPS[op][1], "name": None, "members": None,
             "keys": None, "creator": None, "text": None, "left": left}
        if op in ("create", "accept"):
            s.update(name=GROUP_NAME, members=members, keys=keys)
        if op == "accept":
            s["creator"] = m_hex
        if op == "post":
            s["text"] = POST_TEXT
        return s

    def expected(s, by=DEVICE):
        e = {"by": by, "problem": None}
        e.update(s)
        return e

    def g_vector(name, why, s, fields, timestamp, substitute=None, expect=None):
        packed, message_hash, fields_bytes = pack(d, d_hash, d_hash, timestamp, b"", b"", fields, substitute)
        expect = expect or expected(s)
        got = read_group_sync(msgpack.unpackb(fields_bytes), d_hex)
        assert got == expect, f"{name}: {got} != {expect}"
        return {
            "name": name,
            "why": why,
            "timestamp": timestamp,
            "sync": s,
            "fields_hex": hexs(fields_bytes),
            "packed_hex": hexs(packed),
            "hash_hex": hexs(message_hash),
            "expected": expect,
        }

    # 1. Each op, with an empty and a full left: what set_group_sync_fields
    #    must write, byte for byte, from `sync`.
    ops = []
    for op in OPS:
        for left_name, left in (("empty", []), ("full", LEFT_FULL)):
            s = sync(op, left)
            ops.append(g_vector(f"{op}_{left_name}_left", f"a {op} G with {len(left)} ids in left", s,
                                g_fields(custom_data(s)), OPS[op][0]))

    # 2. Readings a writer here never makes but a receiver must take.
    variants = []
    s = sync("accept", LEFT_FULL)
    at = OPS["accept"][1]
    variants.append(g_vector(
        "accept_web_form_int64_at_ms",
        "the web writes at_ms as int 64 (0xd3); read by value",
        s, g_fields(custom_data(s)), OPS["accept"][0],
        substitute=(b"\xcf" + at.to_bytes(8, "big"), b"\xd3" + at.to_bytes(8, "big"))))
    s = sync("create", [])
    arr = custom_data(s)
    arr[3] = GROUP_NAME.encode()
    variants.append(g_vector("create_name_as_bin", "name may be a bin (UTF-8)", s, g_fields(arr), OPS["create"][0] + 1))
    s = sync("post", [])
    arr = custom_data(s)
    arr[3] = POST_TEXT.encode()
    variants.append(g_vector("post_text_as_bin", "text may be a bin (UTF-8)", s, g_fields(arr), OPS["post"][0] + 1))
    s = sync("leave", LEFT_FULL[:2])
    arr = custom_data(s) + ["a later element", 7]
    variants.append(g_vector("leave_elements_after_left", "elements after left are ignored", s, g_fields(arr),
                             OPS["leave"][0] + 1))
    s = sync("accept", [i.upper() for i in LEFT_FULL[:3]])
    s["group_id"] = GROUP_ID.upper()
    s["creator"] = m_hex.upper()
    exp = expected(dict(s, group_id=GROUP_ID, creator=m_hex, left=LEFT_FULL[:3]))
    variants.append(g_vector("accept_uppercase_ids", "group_id, creator and left ids are read lowercased", s,
                             g_fields(custom_data(s)), OPS["accept"][0] + 1, expect=exp))
    s = sync("create", [])
    s.update(name="", keys=[])
    variants.append(g_vector("create_empty_name_no_keys", "an empty name and no keys", s, g_fields(custom_data(s)),
                             OPS["create"][0] + 2))
    s = sync("create", [])
    s["members"] = f" {d_hex} , {m_hex},not-a-hash,,{OTHER_MEMBER}"
    variants.append(g_vector("create_members_parsed_like_an_invite",
                             "members is parsed with the invite's parser (trimmed, an entry that is not 32 lowercase hex skipped) and kept verbatim",
                             s, g_fields(custom_data(s)), OPS["create"][0] + 3))
    s = sync("accept", [])
    s["members"] = f"\t{d_hex}\u00a0,\u3000{m_hex}\u2009 \u202f,\u205f{OTHER_MEMBER}\u1680\t"
    variants.append(g_vector("accept_members_trimmed_of_zs_and_tab",
                             "the invite parser trims Unicode Zs (here U+0020, U+00A0, U+1680, U+2009, U+202F, U+205F, U+3000) and U+0009 from each entry; D and the creator are listed",
                             s, g_fields(custom_data(s)), OPS["accept"][0] + 2))
    s = sync("post", [])
    s["text"] = ""
    variants.append(g_vector("post_attachment_only", "an attachment-only post copies an empty text", s,
                             g_fields(custom_data(s)), OPS["post"][0] + 2))
    s = sync("leave", [GROUP_ID] + LEFT_FULL[:31])
    variants.append(g_vector("leave_left_names_its_own_group",
                             "left may name G's own group id; the receiver skips it when it applies left", s,
                             g_fields(custom_data(s)), OPS["leave"][0] + 2))
    s = sync("leave", [])
    variants.append(g_vector("leave_without_0xfd", "by is \"\" when 0xFD is absent", s,
                             {k: v for k, v in g_fields(custom_data(s)).items() if k != FIELD_CUSTOM_META},
                             OPS["leave"][0] + 3, expect=expected(s, by="")))
    s = sync("leave", [])
    variants.append(g_vector("leave_0xfd_uppercase", "by is 0xFD lowercased", s,
                             g_fields(custom_data(s), device=DEVICE.upper()), OPS["leave"][0] + 4))
    # by is 0xFD as text only when 0xFD is a str or a bin; any other type gives "".
    s = sync("leave", [])
    variants.append(g_vector("leave_0xfd_int", "by is \"\" when 0xFD is not a str or a bin, here an int", s,
                             {**g_fields(custom_data(s)), FIELD_CUSTOM_META: 5}, OPS["leave"][0] + 5,
                             expect=expected(s, by="")))
    s = sync("leave", [])
    variants.append(g_vector("leave_0xfd_array", "by is \"\" when 0xFD is not a str or a bin, here an array of D's device",
                             s, {**g_fields(custom_data(s)), FIELD_CUSTOM_META: [DEVICE]}, OPS["leave"][0] + 6,
                             expect=expected(s, by="")))
    # The members csv is split on the code point ',', never on grapheme clusters.
    s = sync("accept", [])
    s["members"] = f"{m_hex},{d_hex},́"
    assert invite_members(s["members"]) == [m_hex, d_hex]
    variants.append(g_vector("accept_members_combining_mark_after_a_comma",
                             "members is split on the code point ',' (U+002C), not on grapheme clusters: a combining mark (U+0301) after the last comma is an entry of its own, skipped, and D and the creator M are listed",
                             s, g_fields(custom_data(s)), OPS["accept"][0] + 3))

    # 3. at_ms in every integer encoding, read by value; anything else refused.
    at_ms_encodings = []
    for value, enc, accepted, why in [
        (0, "00", True, "positive fixint 0"),
        (5, "05", True, "positive fixint"),
        (5, "cc05", True, "uint 8"),
        (5, "cd0005", True, "uint 16"),
        (5, "ce00000005", True, "uint 32"),
        (5, "cf0000000000000005", True, "uint 64"),
        (5, "d005", True, "int 8"),
        (5, "d10005", True, "int 16"),
        (5, "d200000005", True, "int 32"),
        (5, "d30000000000000005", True, "int 64"),
        (OPS["leave"][1], "cf" + OPS["leave"][1].to_bytes(8, "big").hex(), True, "uint 64, as rmpv and umsgpack write it"),
        (OPS["leave"][1], "d3" + OPS["leave"][1].to_bytes(8, "big").hex(), True, "int 64, as the web writes it"),
        (MAX_AT_MS, "cf" + MAX_AT_MS.to_bytes(8, "big").hex(), True, "2^53 - 1, the largest"),
        (MAX_AT_MS, "d3" + MAX_AT_MS.to_bytes(8, "big").hex(), True, "2^53 - 1 as int 64"),
        (None, "cf" + (MAX_AT_MS + 1).to_bytes(8, "big").hex(), False, "2^53"),
        (None, "d3" + (MAX_AT_MS + 1).to_bytes(8, "big").hex(), False, "2^53 as int 64"),
        (None, "cf" + "ff" * 8, False, "2^64 - 1"),
        (None, "ff", False, "-1, negative fixint"),
        (None, "d0ff", False, "-1, int 8"),
        (None, "d3" + "ff" * 8, False, "-1, int 64"),
        (None, "cb" + "427a0c4c1ac35000", False, "a float 64"),
        (None, "ca" + "4f000000", False, "a float 32"),
        (None, "ad31373930303030303030303030", False, "a str of digits"),
        (None, "c0", False, "nil"),
        (None, "c3", False, "true"),
    ]:
        arr = ["leave", GROUP_ID, PLACEHOLDER, []]
        fields_bytes = substituted(msgpack.packb(g_fields(arr)),
                                   (b"\xcf" + PLACEHOLDER.to_bytes(8, "big"), bytes.fromhex(enc)))
        got = read_group_sync(msgpack.unpackb(fields_bytes), d_hex)
        assert (got["problem"] is None) == accepted, f"at_ms {enc}: {got}"
        if accepted:
            assert got["at_ms"] == value
        at_ms_encodings.append({"why": why, "at_ms_hex": enc, "at_ms": value, "accepted": accepted,
                                "fields_hex": hexs(fields_bytes)})

    # 4. Each §11.1 rule 4 failure: `problem` set, every other key null.
    def reject(name, why, arr=None, fields=None):
        fields = fields if fields is not None else g_fields(arr)
        fields_bytes = msgpack.packb(fields)
        got = read_group_sync(msgpack.unpackb(fields_bytes), d_hex)
        assert got is not None and got["problem"] is not None, f"{name} is not refused: {got}"
        return {"name": name, "why": why, "fields_hex": hexs(fields_bytes), "by": DEVICE}

    def arr_of(op, **change):
        s = sync(op, [])
        s.update(change)
        return custom_data(s)

    def arr_with(op, index, value):
        a = arr_of(op)
        a[index] = value
        return a

    rejects = [
        reject("fc_absent", "0xFC is absent", fields={k: v for k, v in g_fields([]).items() if k != FIELD_CUSTOM_DATA}),
        reject("fc_bin_of_packed_msgpack", "0xFC is a bin holding packed msgpack, not a native array (CHECK_THESE_THINGS_FIRST §11)",
               fields={**g_fields([]), FIELD_CUSTOM_DATA: msgpack.packb(arr_of("leave"))}),
        reject("fc_str", "0xFC is a str", fields={**g_fields([]), FIELD_CUSTOM_DATA: "leave"}),
        reject("fc_empty_array", "0xFC is an empty array", arr=[]),
        reject("op_unknown", "op is not one of the four", arr=arr_with("leave", 0, "join")),
        reject("op_capitalised", "op is compared exactly", arr=arr_with("leave", 0, "Leave")),
        reject("op_bin", "op is a str, never a bin", arr=arr_with("leave", 0, b"leave")),
        reject("op_int", "op is a str", arr=arr_with("leave", 0, 3)),
        reject("group_id_31_hex", "group_id of 31 hex", arr=arr_with("leave", 1, GROUP_ID[:31])),
        reject("group_id_33_hex", "group_id of 33 hex", arr=arr_with("leave", 1, GROUP_ID + "0")),
        reject("group_id_not_hex", "group_id of 32 characters that are not all hex", arr=arr_with("leave", 1, "g" * 32)),
        reject("group_id_bin", "group_id is a str, never a bin", arr=arr_with("leave", 1, GROUP_ID.encode())),
        reject("at_ms_float", "at_ms is a float", arr=arr_with("leave", 2, 1790000200789.0)),
        reject("at_ms_negative", "at_ms is negative", arr=arr_with("leave", 2, -1)),
        reject("at_ms_2_53", "at_ms is 2^53", arr=arr_with("leave", 2, MAX_AT_MS + 1)),
        reject("leave_too_short", "a leave without left", arr=arr_of("leave")[:3]),
        reject("create_too_short", "a create without left", arr=arr_of("create")[:6]),
        reject("accept_too_short", "an accept without left (the create layout)", arr=arr_of("accept")[:6] + [[]]),
        reject("post_too_short", "a post without left", arr=arr_of("post")[:4]),
        reject("name_int", "name is a str or bin", arr=arr_with("create", 3, 7)),
        reject("name_nil", "name is a str or bin", arr=arr_with("create", 3, None)),
        reject("members_bin", "members is a str, never a bin", arr=arr_with("create", 4, members.encode())),
        reject("members_not_naming_d", "members does not name D", arr=arr_with("create", 4, f"{m_hex},{OTHER_MEMBER}")),
        reject("members_naming_d_in_uppercase_only",
               "the invite parser counts only lowercase 32-hex entries, so an uppercase D is not D",
               arr=arr_with("create", 4, f"{d_hex.upper()},{m_hex}")),
        reject("members_empty", "members is empty", arr=arr_with("accept", 4, "")),
    ] + [
        reject(f"members_naming_d_wrapped_in_{label}",
               f"the invite parser trims only Unicode Zs and U+0009, so D wrapped in {label} ({' '.join(f'U+{ord(c):04X}' for c in wrap)}) is not D",
               arr=arr_with("create", 4, f"{m_hex},{wrap}{d_hex}{wrap}"))
        for label, wrap in [("newline", "\n"), ("cr_lf", "\r\n"), ("vt", "\x0b"), ("ff", "\x0c"),
                            ("unit_separator", "\x1f"), ("file_separator", "\x1c"), ("next_line", "\x85"),
                            ("line_separator", "\u2028"), ("paragraph_separator", "\u2029"),
                            ("byte_order_mark", "\ufeff"), ("zero_width_space", "\u200b")]
    ] + [
        reject("creator_listed_only_wrapped_in_newline",
               "the creator's entry wrapped in U+000A is not listed by the invite parser",
               arr=arr_with("accept", 4, f"{d_hex},\n{m_hex}\n,{OTHER_MEMBER}")),
        reject("keys_str", "keys is an array", arr=arr_with("create", 5, keys[0])),
        reject("keys_with_a_bin", "keys is an array of str", arr=arr_with("create", 5, [keys[0], keys[1].encode()])),
        reject("keys_nil", "keys is an array", arr=arr_with("accept", 5, None)),
        reject("creator_is_d", "creator is D", arr=arr_with("accept", 6, d_hex)),
        reject("creator_not_listed", "creator is not listed", arr=arr_with("accept", 6, "ab" * 16)),
        reject("creator_31_hex", "creator of 31 hex", arr=arr_with("accept", 6, m_hex[:31])),
        reject("creator_bin", "creator is a str", arr=arr_with("accept", 6, m_hex.encode())),
        reject("text_int", "text is a str or bin", arr=arr_with("post", 3, 1)),
        reject("text_nil", "text is a str or bin", arr=arr_with("post", 3, None)),
        reject("left_33_ids", "left holds 33 ids, more than 32", arr=arr_of("leave", left=LEFT_FULL + [GROUP_ID])),
        reject("left_id_31_hex", "a left id of 31 hex", arr=arr_of("post", left=[LEFT_FULL[0][:31]])),
        reject("left_id_bin", "a left id is a str, never a bin", arr=arr_of("leave", left=[LEFT_FULL[0].encode()])),
        reject("left_not_array", "left is an array", arr=arr_with("leave", 3, LEFT_FULL[0])),
        reject("left_nil", "left is an array", arr=arr_with("accept", 7, None)),
        reject("left_in_the_wrong_place",
               "a create whose left is where an accept's creator would be: left must be element 6",
               arr=arr_of("create")[:6] + [m_hex, []]),
        reject("members_naming_d_after_a_combining_mark",
               "a combining mark (U+0301) after a comma and before D's entry is part of that entry, not of the comma (the csv is split on the code point ','), and the invite parser trims only Zs and U+0009, so D is not listed",
               arr=arr_with("create", 4, f"{m_hex},́{d_hex}")),
    ]

    # 5. Messages from a member M to D, through the distro, for the unwrap and
    #    each phone's group receipt (§7: hash, packed, has_group_id, group_id,
    #    group_action, group_name, sender_key, packed, the verdict). M is not
    #    known to the receiver (no announce): the router reports SOURCE_UNKNOWN,
    #    and the receipt decides an accept or leave under the key it carries.
    accept_fields = {0xA0: GROUP_ID, 0xA3: "accept", 0xA4: m_hex, 0xA8: key_entry(m, m_hex)}
    invite_fields = {FIELD_RETICHAT: {1: GROUP_ID, 2: members, 3: GROUP_NAME, 4: "invite", 5: m_hex,
                                      9: key_entry(d, d_hex)}}
    post_fields = {0xA0: GROUP_ID, 0xA4: m_hex}
    web_at = OPS["accept"][1]
    web_form = (b"\xcf" + web_at.to_bytes(8, "big"), b"\xd3" + web_at.to_bytes(8, "big"))
    sealed_specs = [
        # name, signer, src, timestamp, content, fields, expected[, substitute]
        ("g_accept_full_left", d, d_hash, OPS["accept"][0], b"", g_fields(custom_data(sync("accept", LEFT_FULL))),
         {"has_group_id": False, "group_id": None, "group_action": None, "group_name": None,
          "group_sync": expected(sync("accept", LEFT_FULL)), "sender_key_hex": None, "packed": False,
          "signature_validated": True, "unverified_reason": 0,
          "why": "a group sync G from D: validated under the distro key the receiver holds; a distro marker, so no group entries are read"}),
        ("g_accept_web_form_int64_at_ms", d, d_hash, OPS["accept"][0], b"", g_fields(custom_data(sync("accept", LEFT_FULL))),
         {"has_group_id": False, "group_id": None, "group_action": None, "group_name": None,
          "group_sync": expected(sync("accept", LEFT_FULL)), "sender_key_hex": None, "packed": False,
          "signature_validated": True, "unverified_reason": 0,
          "why": "the same G as the web writes it, at_ms as int 64 (0xd3), signed over the payload as sent: LXMF hashes and verifies a payload without a stamp as received (§17.14 rule 2), so the hash is Python's and the signature verifies; packing the payload again (0xcf) gives another hash and a failed signature"},
         web_form),
        ("member_accept_legacy", m, m_hash, 1790000400.5, b"", accept_fields,
         {"has_group_id": True, "group_id": GROUP_ID, "group_action": "accept", "group_name": None,
          "group_sync": None, "sender_key_hex": m.get_public_key().hex(), "packed": True,
          "signature_validated": True, "unverified_reason": 0,
          "why": "M's accept to D in 0xA0-0xA8, carrying M's key: bound to the source, so validated under it"}),
        ("member_accept_forged", x, m_hash, 1790000400.5, b"", accept_fields,
         {"has_group_id": True, "group_id": GROUP_ID, "group_action": "accept", "group_name": None,
          "group_sync": None, "sender_key_hex": m.get_public_key().hex(), "packed": True,
          "signature_validated": False, "unverified_reason": 2,
          "why": "the same accept claiming source M, signed by X: M's carried key binds, the signature fails under it"}),
        ("member_invite_retichat_field", m, m_hash, 1790000000.5, b"", invite_fields,
         {"has_group_id": True, "group_id": GROUP_ID, "group_action": "invite", "group_name": GROUP_NAME,
          "group_sync": None, "sender_key_hex": None, "packed": False,
          "signature_validated": False, "unverified_reason": 1,
          "why": "an invite chunk to D in the Retichat field 0xD1 (D's key in it): not an accept or leave, so the router's verdict stands"}),
        ("member_post_legacy", m, m_hash, 1790000500.5, b"hello from M", post_fields,
         {"has_group_id": True, "group_id": GROUP_ID, "group_action": None, "group_name": None,
          "group_sync": None, "sender_key_hex": None, "packed": False,
          "signature_validated": False, "unverified_reason": 1,
          "why": "a plain group post: no key, no packed copy"}),
    ]

    built = {}
    for name, signer, src, timestamp, content, fields, expect, *substitute in sealed_specs:
        substitute = substitute[0] if substitute else None
        packed, message_hash, fields_bytes = pack(signer, d_hash, src, timestamp, b"", content, fields, substitute)
        if substitute is not None:
            # Not the bytes a packer here makes: the repacked payload hashes otherwise.
            repacked = msgpack.packb(msgpack.unpackb(packed[96:]))
            assert repacked != packed[96:]
            assert RNS.Identity.full_hash(packed[:32] + repacked) != message_hash
        built[name] = (packed, message_hash, fields_bytes, timestamp, content, expect)
    web_variant = next(x for x in variants if x["name"] == "accept_web_form_int64_at_ms")
    assert hexs(built["g_accept_web_form_int64_at_ms"][0]) == web_variant["packed_hex"]

    if "--new-sealed" in sys.argv:
        print(json.dumps({name: d.encrypt(b[0][16:]).hex() for name, b in built.items() if name not in ENCRYPTED},
                         indent=4))
        return
    assert set(ENCRYPTED) == set(built), "run once with --new-sealed and fix ENCRYPTED"

    sealed = []
    for name, (packed, message_hash, fields_bytes, timestamp, content, expect) in built.items():
        encrypted = bytes.fromhex(ENCRYPTED[name])
        assert d.decrypt(encrypted) == packed[16:], f"ENCRYPTED[{name}] is not packed[16:] encrypted to D"
        why = expect.pop("why")
        if expect["group_sync"] is not None:
            assert read_group_sync(msgpack.unpackb(fields_bytes), d_hex) == expect["group_sync"]
        sealed.append({
            "name": name,
            "why": why,
            "timestamp": timestamp,
            "content": content.decode(),
            "fields_hex": hexs(fields_bytes),
            "packed_hex": hexs(packed),
            "hash_hex": hexs(message_hash),
            "blob_hex": hexs(d_hash + encrypted),
            "expected": expect,
        })

    # 6. The group entries the unwrap reports, by the fields alone (has_group_id,
    #    group_id, group_action, group_name; group_sync present or not).
    def entries(name, why, fields, has, gid, action, gname, is_sync=False):
        fields_bytes = msgpack.packb(fields)
        # The reference reads each (an unknown ext as an Ext); a map that
        # repeats a key is a `refused` vector, never one of these.
        assert not reference_refuses(fields_bytes), name
        return {"name": name, "why": why, "fields_hex": hexs(fields_bytes),
                "expected": {"has_group_id": has, "group_id": gid, "group_action": action, "group_name": gname,
                             "group_sync": is_sync}}

    group_entries = [
        entries("retichat_field_invite", "an invite in 0xD1", invite_fields, True, GROUP_ID, "invite", GROUP_NAME),
        entries("legacy_accept", "an accept in 0xA0-0xA8", accept_fields, True, GROUP_ID, "accept", None),
        entries("legacy_name", "GROUP_NAME in 0xA2", {0xA0: GROUP_ID, 0xA2: GROUP_NAME, 0xA3: "invite"}, True,
                GROUP_ID, "invite", GROUP_NAME),
        entries("group_id_int", "a GROUP_ID that is an int: a group message with a malformed id",
                {0xA0: 5, 0xA3: "invite", 0xA2: GROUP_NAME}, True, None, "invite", GROUP_NAME),
        entries("group_id_nil", "a GROUP_ID that is nil still is an entry", {0xA0: None}, True, None, None, None),
        entries("group_id_short", "a GROUP_ID of 31 hex", {0xA0: GROUP_ID[:31]}, True, None, None, None),
        entries("group_id_uppercase", "a GROUP_ID in uppercase is read lowercased", {0xA0: GROUP_ID.upper()}, True,
                GROUP_ID, None, None),
        entries("retichat_field_wins", "key 1 of 0xD1 (a str) wins over 0xA0, even when malformed",
                {FIELD_RETICHAT: {1: "abc"}, 0xA0: GROUP_ID}, True, None, None, None),
        entries("retichat_field_wrong_type", "key 1 of 0xD1 that is not a str gives way to 0xA0",
                {FIELD_RETICHAT: {1: 7}, 0xA0: GROUP_ID}, True, GROUP_ID, None, None),
        entries("retichat_field_not_a_map", "a 0xD1 that is not a map is ignored whole",
                {FIELD_RETICHAT: "x", 0xA0: GROUP_ID}, True, GROUP_ID, None, None),
        entries("retichat_field_int_id_only", "key 1 of 0xD1 of any type is an entry",
                {FIELD_RETICHAT: {1: 7}}, True, None, None, None),
        entries("no_group_entries", "no GROUP_ID in either form", {0xA3: "invite", 0xA2: GROUP_NAME}, False, None,
                None, None),
        entries("other_custom_type", "a 0xFB that is not a distro marker does not hide the group entries",
                {FIELD_CUSTOM_TYPE: "app.example", 0xA0: GROUP_ID}, True, GROUP_ID, None, None),
    ] + [
        entries(f"marker_{marker.split('.')[-1]}", f"a {marker} message that also names a group is never a group message",
                {FIELD_CUSTOM_TYPE: marker, FIELD_CUSTOM_DATA: "ab" * 16, 0xA0: GROUP_ID, 0xA3: "invite",
                 0xA2: GROUP_NAME, FIELD_RETICHAT: {1: GROUP_ID}},
                False, None, None, None, is_sync=(marker == DISTRO_GROUP_TYPE))
        for marker in DISTRO_MARKERS
    ]

    # A bin GROUP_ID, and an ext of a type no reader knows beside a group id.
    group_entries += [
        entries("group_id_bin_in_both_forms",
                "a GROUP_ID that is a bin, in 0xD1 and in 0xA0: a group entry is a str, so a group message with no id",
                {FIELD_RETICHAT: {1: GROUP_ID.encode()}, 0xA0: GROUP_ID.encode()}, True, None, None, None),
        entries("group_id_bin_in_0xd1_str_in_0xa0", "key 1 of 0xD1 that is a bin gives way to 0xA0's str",
                {FIELD_RETICHAT: {1: GROUP_ID.encode()}, 0xA0: GROUP_ID}, True, GROUP_ID, None, None),
        entries("ext_beside_group_id", "an ext of a type no reader knows (5) beside 0xA0 is skipped; the map is read",
                {0xA0: GROUP_ID, 0x77: msgpack.Ext(5, b"\x00")}, True, GROUP_ID, None, None),
        entries("ext_beside_group_id_in_retichat_field",
                "an ext of a type no reader knows (9) beside key 1 of 0xD1 is skipped; the map is read",
                {FIELD_RETICHAT: {1: GROUP_ID, 4: "accept", 10: msgpack.Ext(9, b"\x01\x02\x03\x04")}}, True, GROUP_ID,
                "accept", None),
    ]
    assert len({e["name"] for e in group_entries}) == len(group_entries)

    # 7. The invite parser on its own: the csv is split on the code point ','
    #    (U+002C), never on grapheme clusters.
    invite_cases = []
    for name, why, csv, want in [
        ("combining_mark_after_a_comma",
         "a combining mark (U+0301) after the last comma does not join it: it is an entry of its own, skipped",
         f"{m_hex},{d_hex},́", [m_hex, d_hex]),
        ("combining_mark_before_an_entry",
         "a combining mark (U+0301) after a comma is part of the entry that follows, which is then not 32 lowercase hex",
         f"{m_hex},́{d_hex}", [m_hex]),
    ]:
        assert invite_members(csv) == want, f"{name}: {invite_members(csv)}"
        invite_cases.append({"name": name, "why": why, "csv": csv, "members": want})

    # 8. Repeated keys (RFed SPEC §17.14; James, 2026-10-11: parity). A message
    #    whose payload holds a map, at any depth, that repeats a key is refused
    #    whole, on the direct path and on the distro path, as the reference's
    #    LXMessage.unpack_from_bytes refuses it. Each is signed by its source, so
    #    nothing but the repeat refuses it. A dict holds each key once, so these
    #    are raw maps.
    other_id = LEFT_FULL[0]
    leave_arr = custom_data(sync("leave", []))
    refused_specs = [
        # name, why, signer, src, fields as msgpack bytes
        ("group_id_twice", "two 0xA0 entries, each a group id", m, m_hash,
         raw_map([(0xA0, GROUP_ID), (0xA0, other_id)])),
        ("group_id_twice_one_malformed", "two 0xA0 entries, the first not a group id", m, m_hash,
         raw_map([(0xA0, "x"), (0xA0, GROUP_ID)])),
        ("retichat_field_group_id_twice", "key 1 twice in the Retichat field 0xD1", m, m_hash,
         raw_map([(FIELD_RETICHAT, raw_map([(1, GROUP_ID), (1, other_id)]))])),
        ("retichat_field_twice", "two 0xD1 fields", m, m_hash,
         raw_map([(FIELD_RETICHAT, {1: GROUP_ID, 4: "accept"}), (FIELD_RETICHAT, {1: other_id, 3: GROUP_NAME})])),
        ("group_action_and_name_twice", "0xA3 and 0xA2 twice each beside one 0xA0", m, m_hash,
         raw_map([(0xA0, GROUP_ID), (0xA3, "invite"), (0xA2, GROUP_NAME), (0xA3, "leave"), (0xA2, "Another name")])),
        ("custom_type_twice_marker_first",
         "two 0xFB entries, the group sync marker then a type that is not a distro marker, beside group entries", m, m_hash,
         raw_map([(FIELD_CUSTOM_TYPE, DISTRO_GROUP_TYPE), (FIELD_CUSTOM_TYPE, "app.example"),
                  (FIELD_CUSTOM_DATA, leave_arr), (FIELD_CUSTOM_META, DEVICE), (0xA0, GROUP_ID), (0xA3, "leave")])),
        ("custom_type_twice_marker_last",
         "two 0xFB entries, a type that is not a distro marker then the group sync marker, beside group entries", m, m_hash,
         raw_map([(FIELD_CUSTOM_TYPE, "app.example"), (FIELD_CUSTOM_TYPE, DISTRO_GROUP_TYPE),
                  (FIELD_CUSTOM_DATA, leave_arr), (FIELD_CUSTOM_META, DEVICE), (0xA0, GROUP_ID), (0xA3, "leave")])),
        ("g_leave_0xfb_twice", "a leave G from D whose 0xFB is given twice, another type then the group sync marker", d, d_hash,
         raw_map([(FIELD_TICKET, b""), (FIELD_CUSTOM_TYPE, "app.example"), (FIELD_CUSTOM_TYPE, DISTRO_GROUP_TYPE),
                  (FIELD_CUSTOM_DATA, leave_arr), (FIELD_CUSTOM_META, DEVICE)])),
        ("retichat_field_nested_map_repeats_a_key",
         "well-formed group entries in 0xD1 beside its key 10 (no reader knows it), a map that repeats its key 0", m, m_hash,
         raw_map([(FIELD_RETICHAT, raw_map([(1, GROUP_ID), (4, "accept"), (10, raw_map([(0, "a"), (0, "b")]))]))])),
        ("non_group_field_twice", "a plain message, no group entry, whose renderer field 0x0F is given twice", m, m_hash,
         raw_map([(0x0F, 2), (0x0F, 0)])),
        ("non_group_field_nested_repeat",
         "a group post whose commands field 0x09 is an array holding one map that repeats its key 1", m, m_hash,
         raw_map([(0xA0, GROUP_ID), (0xA4, m_hex), (0x09, Raw(b"\x91" + raw_map([(1, b"a"), (1, b"b")])))])),
    ]
    refused_specs = [spec + ("repeated_key",) for spec in refused_specs]

    # 8b. Unhashable keys (RFed SPEC §17.14; decided 2026-10-11: parity): a
    #     map used as a key, or an array key that holds a map at any depth, is
    #     refused whole as the reference refuses it (UnhashableKeyException).
    #     `reason` is the reference's own, the first refusal in the order
    #     umsgpack reads: a key is read whole before it is judged (a map key
    #     that repeats a key is refused for the repeat), a map key is refused
    #     before its value is read, and an array key's value is read before the
    #     key is hashed (so a repeat in that value is the reason).
    empty_map, empty_array = Raw(b"\x80"), Raw(b"\x90")
    array_holding_map = Raw(b"\x91\x80")
    refused_specs += [
        ("map_key_beside_group_id", "a fields map whose key is an empty map, beside a group id", m, m_hash,
         raw_map([(0xA0, GROUP_ID), (empty_map, 0)]), "unhashable_key"),
        ("map_key_not_empty", "a plain message whose fields map has the key {1: 2}", m, m_hash,
         raw_map([(Raw(msgpack.packb({1: 2})), "x")]), "unhashable_key"),
        ("array_key_holding_a_map", "an accept whose fields map has the key [{}] beside its group entries", m, m_hash,
         raw_map([(0xA0, GROUP_ID), (0xA3, "accept"), (array_holding_map, 0)]), "unhashable_key"),
        ("array_key_holding_a_map_deeper", "a fields key [1, [[{1: 2}]]]: a map at any depth of an array key", m, m_hash,
         raw_map([(Raw(b"\x92\x01\x91\x91\x81\x01\x02"), 0)]), "unhashable_key"),
        ("retichat_field_map_key",
         "well-formed group entries in 0xD1 beside its key 10 (no reader knows it), a map whose key is an empty map", m, m_hash,
         raw_map([(FIELD_RETICHAT, raw_map([(1, GROUP_ID), (4, "accept"), (10, raw_map([(empty_map, 0)]))]))]),
         "unhashable_key"),
        ("non_group_field_nested_map_key",
         "a group post whose commands field 0x09 is an array holding one map whose key is the map {1: 2}", m, m_hash,
         raw_map([(0xA0, GROUP_ID), (0xA4, m_hex), (0x09, Raw(b"\x91" + raw_map([(Raw(b"\x81\x01\x02"), 1)])))]),
         "unhashable_key"),
        ("g_leave_map_key", "a leave G from D whose fields also hold an entry keyed by an empty map", d, d_hash,
         raw_map([(FIELD_TICKET, b""), (FIELD_CUSTOM_TYPE, DISTRO_GROUP_TYPE), (FIELD_CUSTOM_DATA, leave_arr),
                  (FIELD_CUSTOM_META, DEVICE), (empty_map, 0)]), "unhashable_key"),
        ("map_key_that_repeats_a_key", "a fields key that is a map repeating its key 0: the key is read, and refused, first",
         m, m_hash, raw_map([(raw_map([(0, 1), (0, 2)]), 0)]), "repeated_key"),
        ("map_key_whose_value_repeats_a_key",
         "a fields key that is an empty map, whose value repeats its key 0: the map key is refused before its value is read",
         m, m_hash, raw_map([(empty_map, raw_map([(0, 1), (0, 2)]))]), "unhashable_key"),
        ("array_key_holding_a_map_whose_value_repeats_a_key",
         "a fields key [{}] whose value repeats its key 0: an array key's value is read before the key is hashed",
         m, m_hash, raw_map([(array_holding_map, raw_map([(0, 1), (0, 2)]))]), "repeated_key"),
        ("array_key_holding_a_map_then_a_repeat",
         "a fields key [{}], then the key 5 twice: refused at the array key, before the repeat is read", m, m_hash,
         raw_map([(array_holding_map, 0), (5, 1), (5, 2)]), "unhashable_key"),
    ]
    refused = []
    for i, (name, why, signer, src, fields_raw, reason) in enumerate(refused_specs):
        content = b"" if src == d_hash else b"x"
        timestamp = 1790000600.5 + i
        packed = pack_raw(signer, d_hash, src, timestamp, b"", content, fields_raw)
        assert reference_refuses(fields_raw), f"{name}: the fields repeat a key or hold an unhashable one"
        assert reference_verdict(packed) == reason, f"{name}: LXMF.py refuses the message for {reason}"
        refused.append({"name": name, "why": why, "reason": reason, "source": "distro" if src == d_hash else "member",
                        "timestamp": timestamp, "content": content.decode(), "fields_hex": hexs(fields_raw),
                        "packed_hex": hexs(packed)})
    assert len({r["name"] for r in refused}) == len(refused)

    # 9. Which two keys are one key: Python's equality, as umsgpack's `k in d`
    #    tests it. Each is a fields map of two entries, {a: 0, b: 1}.
    key_equality = []
    for i, (name, a, b, is_refused, why) in enumerate([
        ("int_fixint_and_uint8", "01", "cc01", True, "1 as a positive fixint and as uint 8"),
        ("int_uint16_and_int64", "cd00a0", "d300000000000000a0", True, "0xA0 as uint 16 and as int 64"),
        ("int_and_float64", "01", "cb3ff0000000000000", True, "the int 1 and the float 64 1.0"),
        ("int_and_float32", "01", "ca3f800000", True, "the int 1 and the float 32 1.0"),
        ("true_and_int_1", "c3", "01", True, "true and the int 1"),
        ("false_and_int_0", "c2", "00", True, "false and the int 0"),
        ("int_0_and_float_minus_0", "00", "cb8000000000000000", True, "the int 0 and the float 64 -0.0"),
        ("float32_and_float64", "ca3fc00000", "cb3ff8000000000000", True, "1.5 as float 32 and as float 64"),
        ("infinity_float32_and_float64", "ca7f800000", "cb7ff0000000000000", True, "infinity as float 32 and as float 64"),
        ("int_minus_1_int8_and_fixint", "d0ff", "ff", True, "-1 as int 8 and as a negative fixint"),
        ("uint64_max_and_float_2_64", "cfffffffffffffffff", "cb43f0000000000000", False,
         "2^64 - 1 (uint 64) and the float 64 2^64: not one value"),
        ("nan_twice", "cb7ff8000000000000", "cb7ff8000000000000", False, "NaN twice: NaN equals nothing, not even NaN"),
        ("nil_twice", "c0", "c0", True, "nil twice"),
        ("empty_str_twice", "a0", "a0", True, "the empty str twice"),
        ("str_and_bin", "a161", "c40161", False, "the str 'a' and the bin 'a': a str is never a bin"),
        ("int_and_str", "01", "a131", False, "the int 1 and the str '1'"),
        ("str_not_normalised", "a2c3a9", "a365cc81", False,
         "U+00E9 and U+0065 U+0301: a str is compared by its code points, never normalised"),
        ("ext_twice", "d40500", "d40500", True, "the ext (5, 00) twice"),
        ("ext_fixext1_and_ext8", "d40500", "c7010500", True, "the ext (5, 00) as fixext 1 and as ext 8"),
        ("ext_other_type", "d40500", "d40600", False, "the exts (5, 00) and (6, 00)"),
        ("timestamp_32_and_64", "d6ff00000000", "d7ff0000000000000000", True,
         "the timestamp ext (-1) of the epoch as timestamp 32 and as timestamp 64: one instant"),
        ("array_twice", "9101", "9101", False,
         "the array [1] twice: umsgpack never compares an array key (it makes it a tuple and skips the check)"),
        ("empty_array_twice", "90", "90", False,
         "the empty array twice: never compared, and an array key that holds no map is read"),
        ("array_holding_an_array_twice", "919101", "919101", False,
         "the array [[1]] twice: never compared, and an array key that holds no map, at any depth, is read"),
    ]):
        fields_raw = b"\x82" + bytes.fromhex(a) + b"\x00" + bytes.fromhex(b) + b"\x01"
        packed = pack_raw(m, d_hash, m_hash, 1790000700.5 + i, b"", b"x", fields_raw)
        assert reference_refuses(fields_raw) == is_refused, name
        assert reference_verdict(packed) == ("repeated_key" if is_refused else None), name
        key_equality.append({"name": name, "why": why, "keys_hex": [a, b], "refused": is_refused,
                             "fields_hex": hexs(fields_raw), "packed_hex": hexs(packed)})
    assert len({k["name"] for k in key_equality}) == len(key_equality)

    # 10. Nesting (RFed SPEC §17.14; decided 2026-10-11): no value of a payload
    #     deeper than NESTING_MAX_DEPTH (the payload at depth 0, the fields map
    #     at 1, field 0x77's value at 2), Python's propagated delivery path,
    #     measured. Each is a message from M to D whose field 0x77 (no reader
    #     knows it) nests that deep, judged on DELIVERY_FRAMES.
    def field_0x77(value_raw):
        return raw_map([(0x77, value_raw)])

    at, past = NESTING_MAX_DEPTH - 1, NESTING_MAX_DEPTH  # nested containers in field 0x77
    nesting = []
    for i, (name, why, fields_raw, is_refused) in enumerate([
        ("arrays_at_the_limit", f"{at} arrays nested in a field, the innermost empty, at depth {NESTING_MAX_DEPTH}",
         field_0x77(nested(at)), False),
        ("arrays_past_the_limit", f"{past} arrays nested in a field, the innermost empty, at depth {NESTING_MAX_DEPTH + 1}",
         field_0x77(nested(past)), True),
        ("maps_at_the_limit", f"{at} maps {{0: ...}} nested in a field, the innermost empty, at depth {NESTING_MAX_DEPTH}",
         field_0x77(nested(at, b"\x80", "map")), False),
        ("maps_past_the_limit", f"{past} maps {{0: ...}} nested in a field, the innermost empty",
         field_0x77(nested(past, b"\x80", "map")), True),
        ("int_at_the_limit", f"{at - 1} arrays nested in a field, the innermost holding the int 0 at depth {NESTING_MAX_DEPTH}",
         field_0x77(nested(at - 1, b"\x91\x00")), False),
        ("int_past_the_limit", f"{at} arrays nested in a field, the innermost holding the int 0 at depth {NESTING_MAX_DEPTH + 1}",
         field_0x77(nested(at, b"\x91\x00")), True),
        ("str_at_the_limit", f"{at - 1} arrays nested in a field, the innermost holding the str 'a' at depth {NESTING_MAX_DEPTH}",
         field_0x77(nested(at - 1, b"\x91\xa1a")), False),
        ("str_past_the_limit", f"{at} arrays nested in a field, the innermost holding the str 'a' at depth {NESTING_MAX_DEPTH + 1}",
         field_0x77(nested(at, b"\x91\xa1a")), True),
        ("key_at_the_limit", f"a map in a field whose key is {at - 1} nested arrays, the innermost empty at depth {NESTING_MAX_DEPTH}",
         field_0x77(raw_map([(nested(at - 1), 0)])), False),
        ("key_past_the_limit", f"a map in a field whose key is {at} nested arrays, the innermost empty at depth {NESTING_MAX_DEPTH + 1}",
         field_0x77(raw_map([(nested(at), 0)])), True),
        ("far_past_the_limit", "600 arrays nested in a field (past what a decoder may read at all: still refused whole)",
         field_0x77(nested(600)), True),
    ]):
        packed = pack_raw(m, d_hash, m_hash, 1790000800.5 + i, b"", b"x", fields_raw)
        verdict = reference_verdict(packed)
        assert verdict == ("too_deep" if is_refused else None), f"{name}: {verdict}"
        vector = {"name": name, "why": why, "refused": is_refused, "fields_hex": hexs(fields_raw),
                  "packed_hex": hexs(packed)}
        if is_refused:
            vector["reason"] = "too_deep"
        nesting.append(vector)
    assert len({n["name"] for n in nesting}) == len(nesting)

    for set_name, vectors in [("ops", ops), ("variants", variants), ("at_ms_encodings", at_ms_encodings),
                              ("rejects", rejects), ("sealed", sealed), ("group_entries", group_entries)]:
        for vector in vectors:
            assert not reference_refuses(bytes.fromhex(vector["fields_hex"])), f"{set_name}: {vector.get('name', vector.get('why'))}"

    out = {
        "spec": "RFed-rust SPEC.md §17.14 (groups and the distro); GROUPS-DISTRO-DESIGN.md §7, §10, §11.1, §17.1, §19.1",
        "notes": [
            "Generated by LXMF-rust tests/distro_group_sync_vectors.py with the Python reference (RNS 1.5.2, LXMF 1.1.1, RNS.vendor.umsgpack); do not edit by hand. Checked by LXMF-rust tests/distro_group_sync_vectors.rs and by the copies in Retichat-ios rust/retichat-ffi/tests/data and Retichat-android rust/retichat-jni/tests/data; for Retichat-js to assert the same bytes and readings.",
            "All *_hex values are lowercase hex. Identities: private_key_hex is the X25519 private key (32) | Ed25519 seed (32); lxmf_delivery_hash_hex is Destination.hash(identity, 'lxmf', 'delivery'). D is the distro (the same key as distro_sync_vectors.json), M a member, X a key that is not M's.",
            "A G is the LXMF message D packs to itself (dest = src = D): empty title and content, fields {0x0C: bin '', 0xFB: 'rfed.distro.group', 0xFC: native array [op, group_id, at_ms, ...], 0xFD: the sending device's address}, in that order. packed_hex = dest(16) | src(16) | signature(64) | msgpack [timestamp f64, bin title, bin content, fields]; hash_hex = full_hash(dest | src | payload), the LXMF message hash; fields_hex = the fields map alone.",
            "ops: each op with an empty and a full (32) left, as set_group_sync_fields writes it from `sync` (the §7 group_sync object without by and problem) and a timestamp: an implementation that writes `sync` on a message from D to D with that timestamp and packs it must produce packed_hex exactly. `expected` is the §7 group_sync object a receiver reports for it.",
            "variants: forms a receiver must read that a Rust writer does not make (the web's int 64 at_ms, bin name or text, elements after left, uppercase ids, 0xFD absent or uppercase, ...), each with its expected reading. by is 0xFD as text, lowercased, when 0xFD is a str or a bin, else \"\" (absent, an int, an array, ...).",
            "at_ms_encodings: fields of a leave G whose at_ms is written in the encoding at_ms_hex; accepted ones read as at_ms, the others are refused (problem set).",
            "rejects: fields of a G that fails §11.1 rule 4; the reading has `by` and a non-null `problem`, and every other key null. The problem text is each implementation's own.",
            "members is parsed with the phones' invite parser (iOS/Android DeliveryPolicy.members): split on ',', each entry trimmed of invite_space (Unicode Zs and U+0009) at both ends, kept when it is exactly 32 lowercase hex, the first of each; it must name D. creator (an accept) is 32 hex, read lowercased, listed, not D.",
            "invite_space: the code points the invite parser trims, Unicode Zs and U+0009 (Swift's CharacterSet.whitespaces), and no other.",
            "sealed: blobs as RFed hands them to D's devices (blob_hex = D_hash | D.encrypt(packed[16:]); the encryption is random, so these bytes are fixed input), each with the unwrap's expected hash (hash_hex; LXMF.py's: full_hash(dest | src | payload) over the payload as received, packed again only to drop a stamp; g_accept_web_form_int64_at_ms is not in the form a packer makes, so a reader that always packs the payload again gets another hash and a failed signature), packed (packed_hex = blob[0:16] | plaintext) and the §7 keys after each phone's group receipt; sender_key_hex is the 128-hex key (null when none), packed true when the JSON's packed is the base64 of packed_hex, false when null. M is not known to the receiver.",
            "group_entries: the unwrap's has_group_id, group_id, group_action and group_name for a fields map alone, and whether group_sync is set (true) or null (false).",
            "group_entries also hold an ext of an unknown type beside a group id (skipped, the map read) and a bin GROUP_ID (no id, in either form).",
            "invite_members: csv strings and the members the invite parser lists for each. The csv is split on the code point ',' (U+002C), never on grapheme clusters: a combining mark after a comma does not join it (Swift's String.split on Character would), and a combining mark before an entry is part of that entry. variants accept_members_combining_mark_after_a_comma and rejects members_naming_d_after_a_combining_mark are the same two cases in a G.",
            "Repeated keys (RFed SPEC §17.14; James, 2026-10-11: parity): a message whose payload holds a map, at any depth, that repeats a key is refused whole, as Python LXMF refuses it (RNS umsgpack raises DuplicateKeyException in LXMessage.unpack_from_bytes): on the direct path and on the distro path, with a log line, and never shown, stored or applied. No reader of the group entries, the group sync or a channel membership message ever sees such a map. No vector outside refused and key_equality repeats a key.",
            "refused: messages to D whose payload repeats a key or holds an unhashable key, each signed by its source (source 'member' is M, 'distro' is D); packed_hex = dest(16) | src(16) | signature(64) | msgpack [timestamp f64, bin title '', bin content, fields as fields_hex]. Every client refuses each whole: the direct path's unpack of packed_hex, and the distro unwrap of packed_hex[0:16] | D.encrypt(packed_hex[16:]). reason is the reference's own: 'repeated_key' (DuplicateKeyException) or 'unhashable_key' (UnhashableKeyException), the first refusal in the order umsgpack reads the bytes. The generator asserts the reference refuses each, for that reason.",
            "Unhashable keys (RFed SPEC §17.14; decided 2026-10-11: parity): a message whose payload holds a map, at any depth, with a key that is a map, or an array that holds a map at any depth, is refused whole, as Python LXMF refuses it (RNS umsgpack raises UnhashableKeyException): on the direct path and on the distro path, with a log line, and never shown, stored or applied. An array key that holds no map is read (key_equality empty_array_twice, array_holding_an_array_twice). Order, as umsgpack reads: a key is read whole before it is judged; a map key is refused before its value is read; an array key's value is read before the key is hashed.",
            "key_equality: a fields map {a: 0, b: 1} for each pair of keys keys_hex = [a, b], and the message from M to D carrying it (packed_hex as in refused); refused is whether the reference takes a and b for one key and refuses the message. Python's equality: an integer, float or boolean of one numeric value whatever its encoding is one key (1, 1.0, true); NaN is no key's equal; a str by its code points, a bin by its bytes, a str never a bin; nil; an ext by type and data, a timestamp ext (-1) by its instant to the microsecond; an array key is never compared (umsgpack skips the check for it), and one that holds no map is read. A map key, or an array key holding a map, is refused for another reason (UnhashableKeyException): those are in refused.",
            "Nesting (RFed SPEC §17.14; decided 2026-10-11): a message whose payload holds any value (an array, a map, a key, a scalar) deeper than nesting_max_depth (493) is refused whole, the payload at depth 0, its fields map at 1, a field's value at 2: a field holds at most 492 nested arrays or maps, the innermost empty, or 491 when the innermost holds anything. That is Python LXMF's measured delivery-path depth for a propagated message (LXMRouter.message_get_response -> lxmf_propagation -> lxmf_delivery -> unpack_from_bytes, the unpack the 10th frame of its thread, recursion limit 1000: umsgpack raises RecursionError one level deeper); a direct delivery over a link (a Resource, the 7th frame) reads up to two levels more. Measured end to end with LXMF-rust tests/delivery_nesting_probe.py (CPython 3.13.5, RNS 1.5.2, LXMF 1.1.1).",
            "nesting: messages from M to D whose field 0x77 (no reader knows it) nests at the limit (refused false: read) or past it (refused true, reason 'too_deep'), in arrays, in maps, with an int or a str innermost, in a key, and far past it (600 arrays, past any decoder's own limit: still refused whole); packed_hex as in refused. Every client reads or refuses each whole as it says, on the direct path and on the distro path. The generator asserts the reference's verdict for each on the propagated delivery path's stack (10 frames).",
        ],
        "distro": {
            "private_key_hex": D_PRIVATE_KEY.hex(),
            "public_key_hex": d.get_public_key().hex(),
            "identity_hash_hex": d.hash.hex(),
            "lxmf_delivery_hash_hex": d_hex,
        },
        "member": {
            "private_key_hex": M_PRIVATE_KEY.hex(),
            "public_key_hex": m.get_public_key().hex(),
            "identity_hash_hex": m.hash.hex(),
            "lxmf_delivery_hash_hex": m_hex,
        },
        "forger": {
            "private_key_hex": X_PRIVATE_KEY.hex(),
            "public_key_hex": x.get_public_key().hex(),
            "identity_hash_hex": x.hash.hex(),
            "lxmf_delivery_hash_hex": x_hash.hex(),
        },
        "device_hex": DEVICE,
        "group": {"group_id": GROUP_ID, "name": GROUP_NAME, "members": members, "keys": keys, "creator": m_hex,
                  "text": POST_TEXT},
        "left_full": LEFT_FULL,
        "max_at_ms": MAX_AT_MS,
        "nesting_max_depth": NESTING_MAX_DEPTH,
        "invite_space": [ord(c) for c in INVITE_SPACE],
        "ops": ops,
        "variants": variants,
        "at_ms_encodings": at_ms_encodings,
        "rejects": rejects,
        "sealed": sealed,
        "group_entries": group_entries,
        "invite_members": invite_cases,
        "refused": refused,
        "key_equality": key_equality,
        "nesting": nesting,
    }
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "distro_group_sync_vectors.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
