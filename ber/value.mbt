///|
/// The subset of ASN.1 types an SNMP message needs (RFC 3416 §4).
pub(all) enum BerValue {
  /// Universal 2: a signed 32-bit integer.
  Integer(Int)
  /// Universal 4: an opaque byte string (used by OCTET STRING and by
  /// SNMP's IpAddress / Counter32 / TimeTicks / Opaque, which are all
  /// application-typed octet strings on the wire).
  OctetString(Bytes)
  /// Universal 5: the distinguished NULL value, which carries no data.
  Null
  /// Universal 6: an object identifier.
  ObjectIdentifier(@oid.Oid)
  /// Universal 16: an ordered sequence of values (SEQUENCE / PDU).
  Sequence(Array[BerValue])
} derive(Eq, @debug.Debug)

///|
pub extend BerValue with Eq::{not_equal, equal}

///|
pub extend BerValue with @debug.Debug::{to_repr}
