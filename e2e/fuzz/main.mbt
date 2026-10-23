///|
/// Fuzz the three decoders: BER, v1/v2c messages, and v3 messages.
///
///   moon run e2e/fuzz
///
/// The property is narrow and absolute: **for any input at all, decoding
/// returns a value or an error, and never panics.** A panic is not an
/// error value — it escapes every `catch` and takes the process down — so
/// for a receiver, one malformed datagram from a stranger would be a
/// denial of service rather than a packet it ignores.
///
/// Random buffers alone are a weak test: they almost always die at the
/// first tag byte, never reaching the length arithmetic where the bugs
/// live. So three shapes are fed in, and the last two matter most:
///
///   1. random bytes, lengths 0..119;
///   2. every prefix of two valid messages, which walks the truncation
///      boundary one byte at a time;
///   3. every single-byte change of those messages, all 256 values at
///      every position.
///
/// Exits non-zero on a panic, which is what CI reads.
///
/// This found a real one: a four-octet length of `ff ff ff ff` reads as
/// -1 in a 32-bit Int, and the bound check that added it to the offset
/// wrapped, so a six-byte datagram reached the view slice with a negative
/// end. Six bytes. It is now rejected, and this suite is why it stays
/// rejected.

///|
/// A deterministic pseudo-random generator.
///
/// Deliberately weak — it only has to be reproducible and spread out. The
/// constants are small enough that the 32-bit multiply cannot overflow,
/// because an overflowing generator is a bug in the harness and would
/// hide the thing under test.
fn next(state : Array[Int]) -> Int {
  let v = (state[0] * 31 + 7) % 1000003
  state[0] = if v < 0 { v + 1000003 } else { v }
  state[0]
}

///|
fn random_bytes(state : Array[Int], len : Int) -> Bytes {
  let out : Array[Byte] = Array::make(len, (0).to_byte())
  for i in 0..<len {
    out[i] = (next(state) % 256).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn nibble(b : Byte) -> Int {
  let n = b.to_uint().reinterpret_as_int()
  if n >= 0x30 && n <= 0x39 {
    n - 0x30
  } else if n >= 0x61 && n <= 0x66 {
    n - 0x57
  } else {
    abort("not a hex digit")
  }
}

///|
fn unhex(text : String) -> Bytes {
  let src = @utf8.encode(text)
  let out : Array[Byte] = []
  let mut i = 0
  while i + 1 < src.length() {
    out.push(((nibble(src.at(i)) << 4) | nibble(src.at(i + 1))).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
/// Decode `bytes` with all three decoders, swallowing their errors.
///
/// Errors are the expected outcome and are not interesting; a panic is,
/// and it cannot be caught here — it ends the process, which is the
/// signal this program exists to send.
fn try_all(bytes : Bytes) -> Unit {
  try {
    let _ = @ber.BerValue::decode(bytes)
  } catch {
    _ => ()
  }
  try {
    let _ = @pdu.Message::decode(bytes)
  } catch {
    _ => ()
  }
  try {
    let _ = @snmpv3.V3Message::decode(bytes)
  } catch {
    _ => ()
  }
}

///|
fn main {
  let state : Array[Int] = [123456789]
  let mut rounds = 0

  for _ in 0..<6000 {
    let len = next(state) % 120
    try_all(random_bytes(state, len))
    rounds = rounds + 1
  }

  // A v2c GetRequest for sysDescr.0, and the v3 discovery probe: both
  // are real messages, so their prefixes and mutations stay near the
  // shapes that matter.
  let v2c = unhex(
    "302902010104067075626c6963a01c020400000001020100020100300e300c06082b060102010101000500",
  )
  let v3 = unhex(
    "303e020103301102046bb9beba020300ffe30401040201030410300e0400020100020100040004000400301404000400a00e0204215080780201000201003000",
  )
  for whole in [v2c, v3] {
    let mut cut = 0
    while cut <= whole.length() {
      try_all(Bytes::from_array(whole.to_array()[:cut]))
      rounds = rounds + 1
      cut = cut + 1
    }
    let mut at = 0
    while at < whole.length() {
      let mut value = 0
      while value < 256 {
        let mutated = whole.to_array()
        mutated[at] = value.to_byte()
        try_all(Bytes::from_array(mutated))
        rounds = rounds + 1
        value = value + 1
      }
      at = at + 1
    }
  }

  // Text, for the OID parser. Two dots in a row and a stray letter are
  // the shapes a hand-edited config produces.
  let alphabet = "0123456789..x"
  for _ in 0..<3000 {
    let len = next(state) % 24
    let mut text = ""
    for _ in 0..<len {
      text = text + alphabet[next(state) % alphabet.length()].to_string()
    }
    try {
      let _ = @oid.Oid::parse(text)
    } catch {
      _ => ()
    }
    rounds = rounds + 1
  }

  // The decryption path. A wrong key, or a corrupted ciphertext, gives
  // arbitrary bytes that are then parsed as a scoped PDU, so the shapes
  // below are the ones a real receiver meets rather than a hypothetical.
  let engine : @snmpv3.Engine = {
    id: unhex("80001f8880a32a253f0921cb6a00000000"),
    boots: 1,
    time: 100,
  }
  let security : @snmpv3.Security = {
    level: @snmpv3.AuthPriv,
    user: b"fuzz",
    auth_protocol: @snmpv3.Md5,
    auth_password: b"authpass",
    priv_protocol: @snmpv3.Aes128,
    priv_password: b"privpass",
  }
  let keys = security.localize(engine.id) catch {
    _ => abort("the fuzz keys would not localize")
  }
  let salt = unhex("0000000000000001")

  // `decrypt_aes` has to be total: any length of ciphertext, key held
  // fixed. Zero length and the lengths either side of a block boundary
  // are where its arithmetic would go wrong.
  let mut len = 0
  while len < 48 {
    let ciphertext = random_bytes(state, len)
    try {
      let _ = @snmpv3.decrypt_aes(ciphertext, keys.priv_key, engine, salt)
    } catch {
      _ => ()
    }
    rounds = rounds + 1
    len = len + 1
  }

  // `open` on random bytes: decode, verify, decrypt, parse — the whole
  // chain a receiver runs on every datagram.
  for _ in 0..<2000 {
    let len = next(state) % 96
    try_open(random_bytes(state, len), security, keys)
    rounds = rounds + 1
  }

  // And on mutations of a genuinely sealed message. Mutating the
  // ciphertext keeps the envelope intact, so the changes reach the
  // decryption and PDU parsing instead of dying at the outer tag.
  let envelope = seal_sample(engine, security, keys, salt) catch {
    _ => abort("the sample message would not seal")
  }
  let mut at = 0
  while at < envelope.length() {
    let mut value = 0
    while value < 256 {
      let mutated = envelope.to_array()
      mutated[at] = value.to_byte()
      try_open(Bytes::from_array(mutated), security, keys)
      rounds = rounds + 1
      value = value + 1
    }
    at = at + 5
  }

  // Random ciphertext that *passes* authentication, which is the only
  // way to reach the decryption: `open` verifies before it decrypts, so
  // a mutated envelope stops at the authenticator and never gets here.
  // Signing a message whose `data` is already encrypted does exactly
  // that — the authenticator covers the garbage, so it is accepted, and
  // the plaintext handed to the parser is arbitrary.
  let mut attempt = 0
  while attempt < 400 {
    let ciphertext = random_bytes(state, next(state) % 72)
    let message : @snmpv3.V3Message = {
      msg_id: attempt + 1,
      msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
      flags: @snmpv3.MsgFlags::of(@snmpv3.AuthPriv),
      security_model: @snmpv3.USM_SECURITY_MODEL,
      engine,
      user: b"fuzz",
      auth_params: b"",
      priv_params: salt,
      data: @snmpv3.Encrypted(ciphertext),
    }
    let wire = @snmpv3.seal(message, security, keys, salt) catch {
      _ => continue
    }
    try_open(wire, security, keys)
    rounds = rounds + 1
    attempt = attempt + 1
  }

  // Structurally valid BER values with the wrong shape: what decryption
  // hands the PDU decoder when the key is right and the sender is not.
  let shapes : Array[@ber.BerValue] = [
    @ber.BerValue::Tagged(0xA0, []),
    @ber.BerValue::Tagged(0xA0, [@ber.BerValue::Integer(1)]),
    @ber.BerValue::Tagged(0xA0, [
      @ber.BerValue::Integer(1),
      @ber.BerValue::Integer(0),
      @ber.BerValue::Integer(0),
    ]),
    @ber.BerValue::Tagged(0xA0, [
      @ber.BerValue::OctetString(b"x"),
      @ber.BerValue::Integer(0),
      @ber.BerValue::Integer(0),
      @ber.BerValue::Sequence([]),
    ]),
    @ber.BerValue::Tagged(0xA0, [
      @ber.BerValue::Integer(1),
      @ber.BerValue::Integer(999),
      @ber.BerValue::Integer(0),
      @ber.BerValue::Sequence([]),
    ]),
    @ber.BerValue::Tagged(0xA4, []),
    @ber.BerValue::Tagged(0xA4, [
      @ber.BerValue::Integer(1),
      @ber.BerValue::Integer(1),
      @ber.BerValue::Integer(1),
      @ber.BerValue::Integer(1),
      @ber.BerValue::Integer(1),
    ]),
    @ber.BerValue::Tagged(0xA5, [@ber.BerValue::Integer(1)]),
    @ber.BerValue::Tagged(0xFF, []),
    @ber.BerValue::Tagged(0xA2, [
      @ber.BerValue::Integer(1),
      @ber.BerValue::Integer(0),
      @ber.BerValue::Integer(0),
      @ber.BerValue::Sequence([
        @ber.BerValue::Sequence([@ber.BerValue::Integer(1)]),
      ]),
    ]),
    @ber.BerValue::Integer(1),
    @ber.BerValue::Null,
  ]
  for shape in shapes {
    try {
      let _ = @pdu.Pdu::from_ber(shape)
    } catch {
      _ => ()
    }
    rounds = rounds + 1
  }

  println("survived \{rounds} decoder rounds: no input panicked")
}

///|
/// `open` and swallow its error, for the fuzz loops.
fn try_open(
  bytes : Bytes,
  security : @snmpv3.Security,
  keys : @snmpv3.Keys,
) -> Unit {
  try {
    let _ = @snmpv3.open(bytes, security, keys)
  } catch {
    _ => ()
  }
}

///|
/// A sealed authPriv message with a few var-binds, so the ciphertext is
/// long enough that mutations land inside the encrypted region.
fn seal_sample(
  engine : @snmpv3.Engine,
  security : @snmpv3.Security,
  keys : @snmpv3.Keys,
  salt : Bytes,
) -> Bytes raise {
  let varbinds : Array[@pdu.VarBind] = [
    @pdu.VarBind::new(@oid.Oid::parse("1.3.6.1.2.1.1.1.0"), @ber.BerValue::Null),
    @pdu.VarBind::new(@oid.Oid::parse("1.3.6.1.2.1.1.5.0"), @ber.BerValue::Null),
  ]
  let message : @snmpv3.V3Message = {
    msg_id: 7,
    msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
    flags: @snmpv3.MsgFlags::of(@snmpv3.AuthPriv),
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine,
    user: b"fuzz",
    auth_params: b"",
    priv_params: b"",
    data: @snmpv3.Plain({
      context_engine_id: engine.id,
      context_name: b"",
      pdu: @pdu.Pdu::request(@pdu.GetRequest, 42, varbinds),
    }),
  }
  @snmpv3.seal(message, security, keys, salt)
}
