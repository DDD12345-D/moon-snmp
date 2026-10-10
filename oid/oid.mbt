///|
/// An SNMP object identifier: a sequence of unsigned subidentifiers.
///
/// The first component is a root arc (0..2); the second is limited to
/// 39 under roots 0 and 1 because BER packs the pair into one
/// subidentifier `40*a + b` (X.690 §8.19). Subidentifiers may use the
/// full unsigned 32-bit range.
pub struct Oid {
  parts : Array[UInt]
} derive(Eq, @debug.Debug)

///|
pub extend Oid with Eq::{not_equal, equal}

///|
pub extend Oid with @debug.Debug::{to_repr}

///|
/// Build an OID from its subidentifiers, validating the root pair.
/// Raises `OidError` when the pair is not a legal BER arc pair.
pub fn Oid::from_parts(parts : Array[UInt]) -> Oid raise OidError {
  if parts.length() < 2 {
    raise OidError::TooShort(parts.length())
  }
  let a = parts[0]
  let b = parts[1]
  if a > 2 {
    raise OidError::InvalidFirstComponent(a)
  }
  if a < 2 && b >= 40 {
    raise OidError::InvalidSecondComponent(b)
  }
  if a == 2 && b > 0xFFFFFFAF {
    // 80 + b must fit an unsigned 32-bit BER subidentifier, so the
    // largest legal second component under root 2 is 0xFFFFFFAF
    // (4294967215) — see `max second component` in the tests.
    raise OidError::ComponentOverflow
  }
  { parts, }
}

///|
/// Parse an OID from dotted-decimal text, e.g. "1.3.6.1.2.1.1.1.0".
/// Raises `OidError` on empty input, stray characters, empty
/// components, or components that do not fit in 32 bits.
pub fn Oid::parse(text : String) -> Oid raise OidError {
  let bytes = @utf8.encode(text)
  if bytes.length() == 0 {
    raise OidError::Empty
  }
  let parts : Array[UInt] = []
  let mut acc : UInt = 0
  let mut digits = 0
  let mut i = 0
  while i < bytes.length() {
    let c = bytes.at(i)
    if c == b'.' {
      if digits == 0 {
        raise OidError::InvalidCharacter(i)
      }
      parts.push(acc)
      acc = 0
      digits = 0
    } else {
      if c < b'0' || c > b'9' {
        raise OidError::InvalidCharacter(i)
      }
      let d = c.to_uint() - b'\x30'.to_uint()
      if acc > (0xFFFFFFFF - d) / 10 {
        raise OidError::ComponentOverflow
      }
      acc = acc * 10 + d
      digits = digits + 1
    }
    i = i + 1
  }
  if digits == 0 {
    raise OidError::InvalidCharacter(bytes.length())
  }
  parts.push(acc)
  Oid::from_parts(parts)
}

///|
/// Render the OID back to dotted-decimal text.
pub fn Oid::to_dotted(self : Oid) -> String {
  let mut out = self.parts[0].to_string()
  for i in 1..<self.parts.length() {
    out = out + "." + self.parts[i].to_string()
  }
  out
}

///|
/// Compare two OIDs the way SNMP orders them: subidentifier by
/// subidentifier as unsigned numbers, and a proper prefix sorts first
/// (X.690 §8.19.4; this is the ordering `walk` relies on).
/// Returns -1, 0, or 1.
pub fn Oid::compare(self : Oid, other : Oid) -> Int {
  let n = if self.parts.length() < other.parts.length() {
    self.parts.length()
  } else {
    other.parts.length()
  }
  let mut i = 0
  while i < n {
    if self.parts[i] < other.parts[i] {
      return -1
    }
    if self.parts[i] > other.parts[i] {
      return 1
    }
    i = i + 1
  }
  if self.parts.length() < other.parts.length() {
    -1
  } else if self.parts.length() > other.parts.length() {
    1
  } else {
    0
  }
}
