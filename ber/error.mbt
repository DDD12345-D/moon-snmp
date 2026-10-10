///|
/// Errors raised while encoding or decoding BER.
pub suberror BerError {
  /// A tag byte that this library does not know how to handle.
  UnknownTag(Int)
  /// The length field announces more bytes than the input holds.
  Truncated
  /// Length bytes remain after a complete value was decoded.
  TrailingBytes(Int)
  /// An OCTET STRING or INTEGER used an indefinite length; SNMP forbids
  /// the indefinite form (RFC 3416 §8), and it is not implemented.
  IndefiniteLength
  /// The length field used more than the four octets allowed.
  LengthTooLong
  /// An INTEGER did not fit in a signed 32-bit value.
  IntegerOverflow
  /// An OID subidentifier did not fit in 32 bits, or was truncated.
  BadOidContent
  /// The content of a value did not match its tag (for example an odd
  /// number of hex digits, or a non-zero padding byte).
  MalformedContent
}
