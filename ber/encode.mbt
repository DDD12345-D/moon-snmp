///|
/// BER tag octets for the universal types SNMP uses (X.690 §8.1).
/// Primitive types have bit 5 clear; SEQUENCE is constructed.
const TAG_INTEGER : Int = 0x02

///|
const TAG_OCTET_STRING : Int = 0x04

///|
const TAG_NULL : Int = 0x05

///|
const TAG_OID : Int = 0x06

///|
const TAG_SEQUENCE : Int = 0x30

///|
/// Application-class tags for the SNMP-specific types (RFC 2578 §7.1).
const TAG_IP_ADDRESS : Int = 0x40

///|
const TAG_COUNTER32 : Int = 0x41

///|
const TAG_GAUGE32 : Int = 0x42

///|
const TAG_TIMETICKS : Int = 0x43

///|
const TAG_OPAQUE : Int = 0x44

///|
const TAG_COUNTER64 : Int = 0x46

///|
/// Encode a value as a complete BER TLV (tag, length, value).
///
/// SMNP uses the definite short form wherever it fits and the definite
/// long form beyond 127 octets (X.690 §8.1.3.5); the indefinite form is
/// never produced.
pub fn BerValue::encode(self : BerValue) -> Bytes {
  let body = self.encode_body()
  let out : Array[Byte] = []
  out.push(self.tag().to_byte())
  push_length(out, body.length())
  out.append(body)
  Bytes::from_array(out)
}

///|
/// The type octet for this value.
fn BerValue::tag(self : BerValue) -> Int {
  match self {
    Integer(_) => TAG_INTEGER
    OctetString(_) => TAG_OCTET_STRING
    Null => TAG_NULL
    ObjectIdentifier(_) => TAG_OID
    Sequence(_) => TAG_SEQUENCE
    IpAddress(_) => TAG_IP_ADDRESS
    Counter32(_) => TAG_COUNTER32
    Gauge32(_) => TAG_GAUGE32
    TimeTicks(_) => TAG_TIMETICKS
    Opaque(_) => TAG_OPAQUE
    Counter64(_) => TAG_COUNTER64
  }
}

///|
/// Encode only the contents octets, without the tag or length.
fn BerValue::encode_body(self : BerValue) -> Array[Byte] {
  match self {
    Integer(n) => encode_integer(n)
    OctetString(b) => b.to_array()
    Null => []
    ObjectIdentifier(oid) => encode_oid(oid)
    Sequence(items) => {
      let out : Array[Byte] = []
      for item in items {
        out.append(item.encode().to_array())
      }
      out
    }
    // The application types below are unsigned: RFC 2578 §7.1 defines
    // them as non-negative, so no sign octet is ever needed and a value
    // whose top bit is set keeps its full width instead of gaining a
    // leading zero the way a signed INTEGER would.
    IpAddress(b) => encode_ip_address(b)
    Counter32(n) => encode_uint(n.to_uint64())
    Gauge32(n) => encode_uint(n.to_uint64())
    TimeTicks(n) => encode_uint(n.to_uint64())
    Opaque(b) => b.to_array()
    Counter64(n) => encode_uint(n)
  }
}

///|
/// Encode a signed integer in the minimal number of octets required by
/// two's complement (X.690 §8.3.2). Zero is the single octet 0x00.
fn encode_integer(n : Int) -> Array[Byte] {
  let n : Int = n // Int is 32-bit signed on every MoonBit backend we target
  let out : Array[Byte] = []
  if n == 0 {
    out.push(0x00)
    return out
  }
  // Emit the two's-complement bytes little-endian first, then strip
  // redundant leading octets (0x00 before a positive, 0xFF before a
  // negative), then reverse to big-endian.
  let mut v = n
  let le : Array[Int] = []
  while !(v == 0 || v == -1) {
    le.push(v & 0xFF)
    v = v >> 8
  }
  // The loop stops at the sign-fill value; append it to preserve sign.
  le.push(v & 0xFF)
  // Strip a redundant leading octet: 0x00 for non-negative, 0xFF for
  // negative. A value like 0xFF (=-1) keeps its single octet.
  let last = le[le.length() - 1]
  if le.length() > 1 && last == 0x00 && (le[le.length() - 2] & 0x80) == 0 {
    let _ = le.pop()
  }
  if le.length() > 1 && last == 0xFF && (le[le.length() - 2] & 0x80) != 0 {
    let _ = le.pop()
  }
  let mut i = le.length()
  while i > 0 {
    i = i - 1
    out.push(le[i].to_byte())
  }
  out
}

///|
/// Encode an unsigned value in the minimal number of octets. Unlike the
/// signed INTEGER case there is no sign octet: a value whose top bit is
/// set keeps its full width.
fn encode_uint(n : UInt64) -> Array[Byte] {
  let out : Array[Byte] = []
  if n == 0 {
    out.push(0x00)
    return out
  }
  let le : Array[Int] = []
  let mut v = n
  while v != 0 {
    le.push((v & 0xFF).to_int())
    v = v >> 8
  }
  let mut i = le.length()
  while i > 0 {
    i = i - 1
    out.push(le[i].to_byte())
  }
  out
}

///|
/// Encode an IpAddress. RFC 2578 §7.1.5 fixes it at exactly four
/// octets; anything else is a caller error rather than a wire error, so
/// it encodes as-is and the decoder rejects it.
fn encode_ip_address(b : Bytes) -> Array[Byte] {
  b.to_array()
}

///|
/// Encode an OID body: the first two arcs pack into one subidentifier
/// `40*a + b`, and every subidentifier uses base-128 with the high bit
/// set on all but the last octet (X.690 §8.19).
fn encode_oid(oid : @oid.Oid) -> Array[Byte] {
  let parts = oid.parts()
  let out : Array[Byte] = []
  let first : UInt = 40 * parts[0] + parts[1]
  push_base128(out, first)
  let mut i = 2
  while i < parts.length() {
    push_base128(out, parts[i])
    i = i + 1
  }
  out
}

///|
/// Append a base-128 subidentifier, most significant group first.
fn push_base128(out : Array[Byte], value : UInt) -> Unit {
  let groups : Array[Int] = []
  let mut v = value
  while v >= 128 {
    groups.push((v & 0x7F).reinterpret_as_int())
    v = v >> 7
  }
  groups.push(v.reinterpret_as_int())
  let mut i = groups.length()
  while i > 0 {
    i = i - 1
    let last = i == 0
    let byte = if last { groups[i] } else { groups[i] | 0x80 }
    out.push(byte.to_byte())
  }
}

///|
/// Write a BER length field: short form for values up to 127 octets,
/// otherwise the long form with the fewest possible length octets.
fn push_length(out : Array[Byte], len : Int) -> Unit {
  if len < 128 {
    out.push(len.to_byte())
  } else {
    let octets : Array[Int] = []
    let mut v = len
    while v > 0 {
      octets.push(v & 0xFF)
      v = v >> 8
    }
    out.push((0x80 | octets.length()).to_byte())
    let mut i = octets.length()
    while i > 0 {
      i = i - 1
      out.push(octets[i].to_byte())
    }
  }
}
