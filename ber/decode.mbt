///|
/// Decode exactly one BER value from the front of `bytes`.
/// Raises `BerError` if the input is truncated, uses an indefinite or
/// over-long length, carries a tag this library does not handle, or has
/// bytes left over after the first complete value.
pub fn BerValue::decode(bytes : Bytes) -> BerValue raise BerError {
  let (value, used) = decode_at(bytes, 0)
  if used != bytes.length() {
    raise BerError::TrailingBytes(bytes.length() - used)
  }
  value
}

///|
/// Decode one TLV starting at `offset`; returns the value and the number
/// of bytes consumed. Used both by `decode` and, recursively, for the
/// contents of a SEQUENCE.
fn decode_at(bytes : BytesView, offset : Int) -> (BerValue, Int) raise BerError {
  let len = bytes.length()
  if offset >= len {
    raise BerError::Truncated
  }
  let tag = bytes.at(offset).to_uint().reinterpret_as_int()
  let (content_len, length_octets) = decode_length(bytes, offset + 1)
  let start = offset + 1 + length_octets
  let end = start + content_len
  if end > len {
    raise BerError::Truncated
  }
  let body = bytes.exact_view(start~, end~)
  let value = match tag {
    0x02 => BerValue::Integer(decode_integer(body))
    0x04 => BerValue::OctetString(body.to_owned())
    0x05 => decode_null(body)
    0x06 => BerValue::ObjectIdentifier(decode_oid(body))
    0x30 => decode_sequence(body, start)
    _ => raise BerError::UnknownTag(tag)
  }
  (value, 1 + length_octets + content_len)
}

///|
/// Parse a length field beginning at `offset`; returns the content
/// length and how many length octets were consumed (1 for the short
/// form, 1 + n for the long form).
fn decode_length(bytes : BytesView, offset : Int) -> (Int, Int) raise BerError {
  if offset >= bytes.length() {
    raise BerError::Truncated
  }
  let first = bytes.at(offset).to_uint().reinterpret_as_int()
  if first < 0x80 {
    return (first, 1)
  }
  if first == 0x80 {
    // Indefinite length is forbidden in SNMP (RFC 3416 §8).
    raise BerError::IndefiniteLength
  }
  let count = first & 0x7F
  if count > 4 {
    raise BerError::LengthTooLong
  }
  if offset + 1 + count > bytes.length() {
    raise BerError::Truncated
  }
  let mut value = 0
  let mut i = 0
  while i < count {
    value = (value << 8) |
      bytes.at(offset + 1 + i).to_uint().reinterpret_as_int()
    i = i + 1
  }
  (value, 1 + count)
}

///|
/// Decode a two's-complement INTEGER from its contents octets. The
/// value must fit a signed 32-bit integer, which is all SNMP uses.
fn decode_integer(body : BytesView) -> Int raise BerError {
  let n = body.length()
  if n == 0 {
    raise BerError::Truncated
  }
  if n > 4 {
    // Five or more octets can only fit if they are all sign fill, i.e.
    // the value is representable, but SNMP never sends those; reject.
    raise BerError::IntegerOverflow
  }
  let mut value = if (body.at(0).to_uint().reinterpret_as_int() & 0x80) != 0 {
    -1
  } else {
    0
  }
  let mut i = 0
  while i < n {
    value = (value << 8) | (body.at(i).to_uint().reinterpret_as_int() & 0xFF)
    i = i + 1
  }
  value
}

///|
/// NULL carries no contents; anything else is malformed.
fn decode_null(body : BytesView) -> BerValue raise BerError {
  if body.length() != 0 {
    raise BerError::MalformedContent
  }
  BerValue::Null
}

///|
/// Decode an OID body: split the packed first subidentifier, then read
/// base-128 groups until the last octet (high bit clear).
fn decode_oid(body : BytesView) -> @oid.Oid raise BerError {
  if body.length() == 0 {
    raise BerError::Truncated
  }
  let parts : Array[UInt] = []
  let mut acc : UInt = 0
  let mut in_group = false
  let mut i = 0
  while i < body.length() {
    let byte = body.at(i).to_uint().reinterpret_as_int()
    let low = byte & 0x7F
    // Guard the shift against overflowing 32 bits.
    if acc > 0x01FFFFFF {
      raise BerError::BadOidContent
    }
    acc = (acc << 7) | low.reinterpret_as_uint()
    in_group = true
    if (byte & 0x80) == 0 {
      parts.push(acc)
      acc = 0
      in_group = false
    }
    i = i + 1
  }
  if in_group {
    // The final subidentifier had its continuation bit set.
    raise BerError::Truncated
  }
  // Unpack the root arc pair from the first subidentifier.
  let packed = parts[0]
  let (a, b) : (UInt, UInt) = if packed < 40 {
    (0, packed)
  } else if packed < 80 {
    (1, packed - 40)
  } else {
    (2, packed - 80)
  }
  let root : Array[UInt] = [a, b]
  for j in 1..<parts.length() {
    root.push(parts[j])
  }
  @oid.Oid::from_parts(root) catch {
    _ => raise BerError::BadOidContent
  }
}

///|
/// Decode the concatenated TLVs that make up a SEQUENCE body.
fn decode_sequence(body : BytesView, base : Int) -> BerValue raise BerError {
  let items : Array[BerValue] = []
  let mut offset = 0
  while offset < body.length() {
    let (item, used) = decode_at(body, offset)
    items.push(item)
    offset = offset + used
  }
  // `base` is carried only so error positions could be reported relative
  // to the outer buffer later; unused for now.
  let _ = base
  BerValue::Sequence(items)
}
