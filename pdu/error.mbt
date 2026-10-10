///|
/// Errors raised while building or parsing an SNMP message.
pub suberror PduError {
  /// The version field is not 0 (v1), 1 (v2c) or 3 (v3).
  UnsupportedVersion(Int)
  /// A PDU tag this library does not know (RFC 3416 §3).
  UnknownPduTag(Int)
  /// An error-status value outside the defined range.
  UnknownErrorStatus(Int)
  /// A TRAP v1 PDU whose shape does not match RFC 1157.
  MalformedTrap
  /// The message did not have the SEQUENCE { version, community, PDU }
  /// shape RFC 3416 §7 requires.
  MalformedMessage
  /// A Bulk PDU (GetBulkRequest) carried no non-repeaters / max-repetitions.
  MalformedBulkPdu
  /// The underlying BER layer rejected the bytes.
  Ber(@ber.BerError)
}

///|
/// The SNMP protocol version carried in the message header.
pub(all) enum Version {
  /// Version 0: SNMPv1 (RFC 1157).
  V1
  /// Version 1: SNMPv2c (RFC 3416), the common case.
  V2c
  /// Version 3: SNMPv3 (RFC 3414); the header differs, see `v3`.
  V3
} derive(Eq, @debug.Debug)

///|
pub extend Version with Eq::{not_equal, equal}

///|
pub extend Version with @debug.Debug::{to_repr}

///|
/// Map a version to the integer that travels in the message header.
pub fn Version::to_int(self : Version) -> Int {
  match self {
    V1 => 0
    V2c => 1
    V3 => 3
  }
}

///|
/// Parse the version integer, rejecting anything RFC 3416 §7 does not
/// define. Note the gap at 2, which was never assigned.
pub fn Version::from_int(n : Int) -> Version raise PduError {
  match n {
    0 => V1
    1 => V2c
    3 => V3
    other => raise PduError::UnsupportedVersion(other)
  }
}
