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

  println("survived \{rounds} decoder rounds: no input panicked")
}
