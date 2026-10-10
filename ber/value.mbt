///|
/// The ASN.1 types an SNMP message needs (RFC 3416 §4, RFC 3418).
///
/// Everything from `Integer` through `Sequence` is a universal (class
/// 0) type. The application-class types below (`IpAddress` onwards) use
/// tag numbers 0x40..0x46 and are how SNMP distinguishes the values in
/// a var-bind: the same wire shape means different things depending on
/// the tag, so they get their own variants instead of being lumped into
/// `OctetString`.
///
/// Note that BER has other classes too (context 0x80, private 0xC0);
/// SNMP uses the context class only for PDU type tags, which live one
/// layer up in `pdu`, not here.
pub(all) enum BerValue {
  /// Universal 2: a signed 32-bit integer.
  Integer(Int)
  /// Universal 4: an opaque byte string.
  OctetString(Bytes)
  /// Universal 5: the distinguished NULL value, which carries no data.
  Null
  /// Universal 6: an object identifier.
  ObjectIdentifier(@oid.Oid)
  /// Universal 16: an ordered sequence of values (SEQUENCE / PDU).
  Sequence(Array[BerValue])
  /// Application 0 (tag 0x40): a 4-octet IPv4 address (RFC 2578 §7.1.5).
  IpAddress(Bytes)
  /// Application 1 (tag 0x41): an unsigned 32-bit counter that wraps
  /// (RFC 2578 §7.1.6).
  Counter32(UInt)
  /// Application 2 (tag 0x42): an unsigned 32-bit value that does not
  /// wrap (RFC 2578 §7.1.7).
  Gauge32(UInt)
  /// Application 3 (tag 0x43): hundredths of a second since some epoch
  /// (RFC 2578 §7.1.8).
  TimeTicks(UInt)
  /// Application 4 (tag 0x44): an opaque byte string whose meaning is
  /// defined by the MIB object (RFC 2578 §7.1.9).
  Opaque(Bytes)
  /// Application 6 (tag 0x46): an unsigned 64-bit counter (RFC 2578
  /// §7.1.10; there is no tag 5, which `Counter64` never reused).
  Counter64(UInt64)
} derive(Eq, @debug.Debug)

///|
pub extend BerValue with Eq::{not_equal, equal}

///|
pub extend BerValue with @debug.Debug::{to_repr}
