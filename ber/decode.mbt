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
    0x40 => BerValue::IpAddress(decode_ip_address(body))
    0x41 => BerValue::Counter32(decode_uint32(body))
    0x42 => BerValue::Gauge32(decode_uint32(body))
    0x43 => BerValue::TimeTicks(decode_uint32(body))
    0x44 => BerValue::Opaque(body.to_owned())
    0x46 => BerValue::Counter64(decode_uint64(body))
    // Any other constructed tag (SEQUENCE 0x30 plus the context-class
    // PDU tags 0xA0..0xA8 and v3 header tags) decodes as a list of
    // nested TLVs, keeping the tag byte so callers can tell them apart.
    _ =>
      if (tag & 0x20) != 0 {
        BerValue::Tagged(tag, decode_sequence_items(body))
      } else if tag >= 0x80 && tag <= 0x82 && body.length() == 0 {
        // The SNMPv2 exceptions (RFC 3416 §4.2.1): noSuchObject
        // (0x80), noSuchInstance (0x81) and endOfMibView (0x82) are
        // context-class *primitive* tags with no content. A GET for an
        // OID the agent does not have returns one of these in place of
        // a value, so they must decode rather than raise.
        BerValue::Tagged(tag, [])
      } else {
        raise BerError::UnknownTag(tag)
      }
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
/// Decode the 4-octet contents of an IpAddress (RFC 2578 §7.1.5). The
/// width is fixed by the MIB definition, so a different length is
/// malformed rather than merely unusual.
fn decode_ip_address(body : BytesView) -> Bytes raise BerError {
  if body.length() != 4 {
    raise BerError::MalformedContent
  }
  body.to_owned()
}

///|
/// Decode an unsigned 32-bit application value (Counter32, Gauge32,
/// TimeTicks). These never carry a sign octet, so the raw octets are
/// the value; up to four of them are legal, and a leading 0x00 is
/// tolerated because some agents pad. Anything wider cannot fit.
fn decode_uint32(body : BytesView) -> UInt raise BerError {
  let n = body.length()
  if n == 0 {
    raise BerError::Truncated
  }
  // The application types are INTEGERs restricted to non-negative values,
  // so a value with the top bit set arrives with a leading zero octet to
  // keep it non-negative. Rejecting that, as this once did, refuses a
  // perfectly legal message: net-snmp encodes ifSpeed 4294967295 exactly
  // that way, so walking the interface table failed on the one interface
  // reporting a saturated link speed.
  let first = first_content_octet(body)
  if n - first > 4 {
    raise BerError::IntegerOverflow
  }
  let mut value : UInt = 0
  let mut i = first
  while i < n {
    value = (value << 8) | body.at(i).to_uint()
    i = i + 1
  }
  value
}

///|
/// Decode an unsigned 64-bit Counter64 (RFC 2578 §7.1.10).
fn decode_uint64(body : BytesView) -> UInt64 raise BerError {
  let n = body.length()
  if n == 0 {
    raise BerError::Truncated
  }
  // Same rule as the 32-bit case.
  let first = first_content_octet(body)
  if n - first > 8 {
    raise BerError::IntegerOverflow
  }
  let mut value : UInt64 = 0
  let mut i = first
  while i < n {
    value = (value << 8) | body.at(i).to_uint64()
    i = i + 1
  }
  value
}

///|
/// Where the value starts in a non-negative INTEGER-shaped content.
///
/// Zero is one octet, and a value whose top bit is set carries exactly
/// one leading zero octet so that it stays non-negative. That single zero
/// is accepted; any other leading zero is redundant, which X.690 §8.3.2
/// does not allow, and is rejected rather than quietly accepted so that a
/// malformed frame is still noticed.
fn first_content_octet(body : BytesView) -> Int raise BerError {
  let n = body.length()
  if n == 1 || body.at(0) != 0x00 {
    return 0
  }
  if (body.at(1).to_uint() & 0x80) == 0 {
    raise BerError::MalformedContent
  }
  1
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
  let _ = base
  BerValue::Sequence(decode_sequence_items(body))
}

///|
/// Decode the concatenated TLVs of any constructed value's body.
fn decode_sequence_items(body : BytesView) -> Array[BerValue] raise BerError {
  let items : Array[BerValue] = []
  let mut offset = 0
  while offset < body.length() {
    let (item, used) = decode_at(body, offset)
    items.push(item)
    offset = offset + used
  }
  items
}
