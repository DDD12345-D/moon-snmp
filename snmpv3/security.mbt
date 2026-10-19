///|
/// The User-based Security Model (RFC 3414), plus the AES privacy
/// protocol that replaced DES (RFC 3826).
///
/// USM turns a password into a key, and a key into two things: a
/// message authenticator that proves who sent it, and — optionally — a
/// cipher that hides what was sent.
///
/// The password never goes on the wire, and neither does the key that
/// comes from it. What travels is an authenticator computed over the
/// whole message, and the message is re-checked against a clock
/// (`engineBoots` / `engineTime`) so that a recorded message cannot be
/// replayed later. That clock is why a v3 client must discover the
/// engine before it can authenticate anything.

///|
/// The authentication protocols USM defines.
pub(all) enum AuthProtocol {
  /// No authentication.
  None
  /// HMAC-MD5-96 (RFC 3414 §6). Deprecated by RFC 7860 §1, kept because
  /// devices in the field still use it.
  Md5
  /// HMAC-SHA-96 (RFC 3414 §7). Also deprecated, for the same reason.
  Sha1
  /// HMAC-SHA-224 truncated to 16 octets (RFC 7860 §5).
  Sha224
  /// HMAC-SHA-256 truncated to 24 octets — the one RFC 7860 §1 says
  /// implementations SHOULD support.
  Sha256
  /// HMAC-SHA-384 truncated to 32 octets.
  Sha384
  /// HMAC-SHA-512 truncated to 48 octets — the other one RFC 7860 §1
  /// says SHOULD.
  Sha512
} derive(Eq, @debug.Debug)

///|
pub extend AuthProtocol with Eq::{not_equal, equal}

///|
pub extend AuthProtocol with @debug.Debug::{to_repr}

///|
/// The privacy protocols this library implements.
///
/// DES is not here. RFC 3414 defines it, RFC 3826 deprecates it, and
/// every deployment that can use AES should; a library that offers only
/// AES is not a gap worth papering over with a weak cipher.
pub(all) enum PrivProtocol {
  /// No encryption.
  None
  /// AES-128 in CFB mode (RFC 3826).
  Aes128
} derive(Eq, @debug.Debug)

///|
pub extend PrivProtocol with Eq::{not_equal, equal}

///|
pub extend PrivProtocol with @debug.Debug::{to_repr}

///|
/// How to talk to an engine: as whom, and with how much protection.
pub(all) struct Security {
  level : SecurityLevel
  /// The user name, as an OCTET STRING because it is not required to be
  /// text.
  user : Bytes
  auth_protocol : AuthProtocol
  /// The password, not the key: localization needs the engine id, which
  /// is not known until discovery has run.
  auth_password : Bytes
  priv_protocol : PrivProtocol
  priv_password : Bytes
} derive(Eq, @debug.Debug)

///|
pub extend Security with Eq::{not_equal, equal}

///|
pub extend Security with @debug.Debug::{to_repr}

///|
/// The keys derived from a password and an engine id.
pub(all) struct Keys {
  /// The localized authentication key: 16 octets for MD5, 20 for SHA-1.
  auth_key : Bytes
  /// The localized privacy key, whose first 16 octets are the AES key.
  priv_key : Bytes
} derive(Eq, @debug.Debug)

///|
pub extend Keys with Eq::{not_equal, equal}

///|
pub extend Keys with @debug.Debug::{to_repr}

///|
/// How many octets of the digest become the message authenticator.
///
/// RFC 3414 fixes this at twelve for both of its protocols; RFC 7860
/// truncates to 16, 24, 32 and 48 octets, and the field on the wire is
/// exactly that long. Nothing may be assumed about the length without
/// asking the protocol.
pub fn AuthProtocol::auth_param_length(self : AuthProtocol) -> Int {
  match self {
    None => 0
    Md5 | Sha1 => 12
    Sha224 => 16
    Sha256 => 24
    Sha384 => 32
    Sha512 => 48
  }
}

///|
/// The size of the key the password is stretched and localized to: the
/// digest size of the hash (RFC 3414 §2.6, RFC 7860 §9.3).
pub fn AuthProtocol::key_length(self : AuthProtocol) -> Int {
  match self {
    None => 0
    Md5 => 16
    Sha1 => 20
    Sha224 => 28
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
/// RFC 3414 §2.6 and A.2.1: the password is stretched to one megabyte by
/// repetition and hashed, and the result is combined with the engine id
/// to make a key that is useless on any other engine.
///
/// The stretching is not a password hash in the modern sense — a
/// megabyte of a repeated password is cheap to compute. It is what the
/// protocol specifies, and it at least means a key is not the password.
pub fn Security::localize(
  self : Security,
  engine_id : Bytes,
) -> Keys raise V3Error {
  let auth_key = match self.auth_protocol {
    None => b""
    protocol => localize_with(self.auth_password, engine_id, protocol)
  }
  let priv_key = match self.priv_protocol {
    None => b""
    Aes128 =>
      // RFC 3414 §2.6: the privacy key uses the *authentication*
      // protocol's hash, not a hash of its own, so a session that
      // authenticates with SHA derives an AES key with SHA.
      match self.auth_protocol {
        None =>
          raise V3Error::NotReady(
            "AES privacy needs an authentication protocol",
          )
        h => localize_with(self.priv_password, engine_id, h)
      }
  }
  { auth_key, priv_key, }
}

///|
/// The number of octets RFC 3414 A.2.1 stretches a password to.
const KEY_STRETCH : Int = 1048576

///|
/// `Kul = H(Ku || engineID || Ku)`, where `Ku` is the stretched password.
fn localize_with(
  password : Bytes,
  engine_id : Bytes,
  protocol : AuthProtocol,
) -> Bytes raise V3Error {
  if password.length() == 0 {
    raise V3Error::NotReady("a password is required")
  }
  let ku = hash_of(protocol, stretched(password))
  let joined : Array[Byte] = []
  joined.append(ku.to_array())
  joined.append(engine_id.to_array())
  joined.append(ku.to_array())
  hash_of(protocol, Bytes::from_array(joined))
}

///|
/// The password repeated to exactly one megabyte.
fn stretched(password : Bytes) -> Bytes raise V3Error {
  if password.length() == 0 {
    raise V3Error::NotReady("a password is required")
  }
  let out : Array[Byte] = Array::make(KEY_STRETCH, 0)
  let mut i = 0
  while i < KEY_STRETCH {
    out[i] = password.at(i % password.length())
    i = i + 1
  }
  Bytes::from_array(out)
}

///|
/// The hash a protocol names.
fn hash_of(protocol : AuthProtocol, message : Bytes) -> Bytes raise V3Error {
  match protocol {
    None => raise V3Error::NotReady("no hash for an unauthenticated session")
    Md5 => @md5.hash(message)
    Sha1 => @sha1.hash(message)
    Sha224 => @sha2.hash(message, kind=@sha2.Sha224)
    Sha256 => @sha2.hash(message, kind=@sha2.Sha256)
    Sha384 => @sha2.hash(message, kind=@sha2.Sha384)
    Sha512 => @sha2.hash(message, kind=@sha2.Sha512)
  }
}

///|
/// The hash factory `hmac` wants, for a protocol.
fn hasher_of(protocol : AuthProtocol) -> (() -> &@spec.Hash) raise V3Error {
  match protocol {
    None => raise V3Error::NotReady("no hash for an unauthenticated session")
    Md5 => md5_hasher
    Sha1 => sha1_hasher
    Sha224 => sha224_hasher
    Sha256 => sha256_hasher
    Sha384 => sha384_hasher
    Sha512 => sha512_hasher
  }
}

///|
fn md5_hasher() -> &@spec.Hash {
  @md5.Hasher::new()
}

///|
fn sha1_hasher() -> &@spec.Hash {
  @sha1.Hasher::new()
}

///|
fn sha224_hasher() -> &@spec.Hash {
  @sha2.Hasher::new(kind=@sha2.Sha224)
}

///|
fn sha256_hasher() -> &@spec.Hash {
  @sha2.Hasher::new(kind=@sha2.Sha256)
}

///|
fn sha384_hasher() -> &@spec.Hash {
  @sha2.Hasher::new(kind=@sha2.Sha384)
}

///|
fn sha512_hasher() -> &@spec.Hash {
  @sha2.Hasher::new(kind=@sha2.Sha512)
}

///|
/// The message authenticator: HMAC truncated to twelve octets (RFC 3414
/// §6.3.1 and §6.3.2 — SHA-1's digest is longer, and the extra is
/// dropped).
pub fn auth_digest(
  protocol : AuthProtocol,
  key : Bytes,
  message : Bytes,
) -> Bytes raise V3Error {
  let full = @hmac.mac(key, message, hasher_of(protocol))
  Bytes::from_array(full.to_array()[:protocol.auth_param_length()])
}

///|
/// Compare two authenticators without leaking where they differ.
///
/// A byte-by-byte comparison that stops at the first difference tells an
/// attacker how much of a guess was right. Twelve octets is short enough
/// that this matters.
pub fn constant_time_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  let mut i = 0
  while i < a.length() {
    diff = diff | (a.at(i).to_uint() ^ b.at(i).to_uint()).reinterpret_as_int()
    i = i + 1
  }
  diff == 0
}

///|
/// Read a BER length field. Returns the length and how many octets the
/// field itself took.
fn read_length(bytes : Bytes, offset : Int) -> (Int, Int) raise V3Error {
  if offset >= bytes.length() {
    raise V3Error::Malformed("a length field runs past the end of the message")
  }
  let first = bytes.at(offset).to_uint().reinterpret_as_int()
  if (first & 0x80) == 0 {
    (first, 1)
  } else {
    let n = first & 0x7F
    if n == 0 {
      raise V3Error::Malformed("an indefinite length is not allowed in SNMP")
    }
    if n > 4 {
      raise V3Error::Malformed("a length field wider than four octets")
    }
    let mut length = 0
    let mut i = 0
    while i < n {
      length = (length << 8) |
        bytes.at(offset + 1 + i).to_uint().reinterpret_as_int()
      i = i + 1
    }
    (length, 1 + n)
  }
}

///|
/// A field's content range in the raw bytes: where it starts and where it
/// ends.
struct Span {
  start : Int
  end : Int
}

///|
/// Walk one TLV at `offset`, returning the tag and the content span.
fn read_tlv(bytes : Bytes, offset : Int) -> (Int, Span) raise V3Error {
  if offset >= bytes.length() {
    raise V3Error::Malformed("a field runs past the end of the message")
  }
  let tag = bytes.at(offset).to_uint().reinterpret_as_int()
  let (length, length_octets) = read_length(bytes, offset + 1)
  let start = offset + 1 + length_octets
  let end = start + length
  if end > bytes.length() {
    raise V3Error::Malformed(
      "a field claims more octets than the message holds",
    )
  }
  (tag, { start, end, })
}

///|
/// The `index`-th child TLV inside a content span, counting from zero.
fn nth_child(
  bytes : Bytes,
  span : Span,
  index : Int,
) -> (Int, Span) raise V3Error {
  let mut offset = span.start
  let mut seen = 0
  while offset < span.end {
    let (tag, child) = read_tlv(bytes, offset)
    if seen == index {
      return (tag, child)
    }
    seen = seen + 1
    offset = child.end
  }
  raise V3Error::Malformed("the message has fewer fields than expected")
}

///|
/// Where the message authenticator lives in an encoded message.
///
/// Verification and signing both need this: the authenticator is
/// computed over the message *with its own field set to zeros*, so one
/// of them has to find that field and blank it, and the other has to
/// find it and fill it in.
///
/// The path is fixed by RFC 3412 §6: the message SEQUENCE's third field
/// is the security parameters, and inside the USM SEQUENCE the fifth
/// field is the authenticator.
pub fn auth_field_span(message : Bytes) -> Span raise V3Error {
  let (_, outer) = read_tlv(message, 0)
  let (_, security_parameters) = nth_child(message, outer, 2)
  // Those parameters are themselves a SEQUENCE encoded into an OCTET
  // STRING, so the walk starts again inside them.
  let (_, usm) = read_tlv(message, security_parameters.start)
  let (_, auth) = nth_child(message, usm, 4)
  auth
}

///|
/// Sign a message in place: blank the authenticator, compute the digest
/// over the result, and write the digest where the blanks were.
///
/// Signing over the blanked form is what the protocol asks for, and it
/// is why the field has a fixed length: the message that is hashed and
/// the message that is sent are the same length, so nothing shifts.
pub fn sign(
  message : Bytes,
  protocol : AuthProtocol,
  key : Bytes,
) -> Bytes raise V3Error {
  let span = auth_field_span(message)
  let expected = protocol.auth_param_length()
  if span.end - span.start != expected {
    raise V3Error::Malformed(
      "the authenticator field is \{span.end - span.start} octets, not \{expected}",
    )
  }
  let out = message.to_array()
  // Blank it, digest it, put the digest back.
  let mut i = span.start
  while i < span.end {
    out[i] = 0
    i = i + 1
  }
  let blanked = Bytes::from_array(out)
  let digest = auth_digest(protocol, key, blanked)
  let signed = blanked.to_array()
  let mut j = 0
  while j < digest.length() {
    signed[span.start + j] = digest.at(j)
    j = j + 1
  }
  Bytes::from_array(signed)
}

///|
/// Check a message's authenticator against a key.
///
/// Returns false for a message that is not authenticated at all, so a
/// caller requiring authentication cannot be fooled by an unauthenticated
/// message that happens to decode.
pub fn verify(
  message : Bytes,
  protocol : AuthProtocol,
  key : Bytes,
) -> Bool raise V3Error {
  let span = auth_field_span(message)
  if span.end - span.start != protocol.auth_param_length() {
    // No room for this protocol's authenticator: not signed that way.
    return false
  }
  let received = Bytes::from_array(message.to_array()[span.start:span.end])
  let blanked = message.to_array()
  let mut i = span.start
  while i < span.end {
    blanked[i] = 0
    i = i + 1
  }
  let expected = auth_digest(protocol, key, Bytes::from_array(blanked))
  constant_time_equal(received, expected)
}

///|
/// Encrypt a scoped PDU with AES-128 in CFB mode (RFC 3826).
///
/// The initial vector is the engine's clock followed by the salt, which
/// is why the clock travels in the clear even for an encrypted message:
/// the receiver needs it to build the same vector, and it can only use
/// the message if the clock is close to its own.
pub fn encrypt_aes(
  plaintext : Bytes,
  key : Bytes,
  engine : Engine,
  salt : Bytes,
) -> Bytes raise V3Error {
  let cipher = aes_cipher(key)
  let iv = Bytes::from_array(
    big_endian(engine.boots, 4) + big_endian(engine.time, 4) + salt.to_array(),
  )
  if iv.length() != 16 {
    raise V3Error::NotReady("the AES initial vector must be sixteen octets")
  }
  let out : Array[Byte] = []
  let mut feedback = iv
  let mut offset = 0
  while offset < plaintext.length() {
    let keystream = cipher.encrypt(feedback)
    let mut block = 0
    let ciphertext_block : Array[Byte] = []
    while block < 16 && offset + block < plaintext.length() {
      let b = plaintext.at(offset + block).to_uint() ^
        keystream.at(block).to_uint()
      out.push(b.to_byte())
      ciphertext_block.push(b.to_byte())
      block = block + 1
    }
    // CFB feeds the ciphertext back: the next keystream comes from
    // encrypting what was just produced.
    let next : Array[Byte] = []
    let mut k = 0
    while k < ciphertext_block.length() {
      next.push(ciphertext_block[k])
      k = k + 1
    }
    // A short final block still needs sixteen octets of feedback; the
    // remaining octets are never used because the loop ends.
    while next.length() < 16 {
      next.push(0)
    }
    feedback = Bytes::from_array(next)
    offset = offset + block
  }
  Bytes::from_array(out)
}

///|
/// Undo `encrypt_aes`.
pub fn decrypt_aes(
  ciphertext : Bytes,
  key : Bytes,
  engine : Engine,
  salt : Bytes,
) -> Bytes raise V3Error {
  let cipher = aes_cipher(key)
  let iv = Bytes::from_array(
    big_endian(engine.boots, 4) + big_endian(engine.time, 4) + salt.to_array(),
  )
  if iv.length() != 16 {
    raise V3Error::NotReady("the AES initial vector must be sixteen octets")
  }
  let out : Array[Byte] = []
  let mut feedback = iv
  let mut offset = 0
  while offset < ciphertext.length() {
    let keystream = cipher.encrypt(feedback)
    let mut block = 0
    let next : Array[Byte] = []
    while block < 16 && offset + block < ciphertext.length() {
      let c = ciphertext.at(offset + block)
      let p = c.to_uint() ^ keystream.at(block).to_uint()
      out.push(p.to_byte())
      next.push(c)
      block = block + 1
    }
    while next.length() < 16 {
      next.push(0)
    }
    feedback = Bytes::from_array(next)
    offset = offset + block
  }
  Bytes::from_array(out)
}

///|
/// An AES cipher for the first sixteen octets of a localized key.
fn aes_cipher(key : Bytes) -> @aes.Cipher raise V3Error {
  if key.length() < 16 {
    raise V3Error::NotReady(
      "an AES key needs sixteen octets; the localized key has \{key.length()}",
    )
  }
  @aes.Cipher::new(key[:16]) catch {
    _ => raise V3Error::NotReady("the AES key was rejected")
  }
}

///|
/// A non-negative integer as big-endian octets, which is what the AES
/// initial vector needs (and what the engine clock uses on the wire).
pub fn big_endian(value : Int, width : Int) -> Array[Byte] {
  let out : Array[Byte] = Array::make(width, 0)
  let mut v = value
  let mut i = width
  while i > 0 {
    i = i - 1
    out[i] = (v & 0xFF).to_byte()
    v = v >> 8
  }
  out
}
