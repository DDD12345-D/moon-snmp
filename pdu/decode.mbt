///|
/// Decode a complete SNMP message from its wire bytes
/// (RFC 3416 §7): `SEQUENCE { version, community, PDU }`.
pub fn Message::decode(bytes : Bytes) -> Message raise PduError {
  let outer = decode_ber(bytes)
  let fields = match outer {
    @ber.BerValue::Sequence(items) => items
    _ => raise PduError::MalformedMessage
  }
  if fields.length() != 3 {
    raise PduError::MalformedMessage
  }
  let version = Version::from_int(expect_integer(fields[0]))
  let community = match fields[1] {
    @ber.BerValue::OctetString(b) => b
    _ => raise PduError::MalformedMessage
  }
  let pdu = decode_pdu(fields[2])
  { version, community, pdu, }
}

///|
/// Decode one BER value, folding any BER error into `PduError::Ber` so
/// callers have a single error type to handle.
fn decode_ber(bytes : Bytes) -> @ber.BerValue raise PduError {
  @ber.BerValue::decode(bytes) catch {
    @ber.BerError::UnknownTag(tag) => raise PduError::UnknownPduTag(tag)
    e => raise PduError::Ber(e)
  }
}

///|
/// Pull an INTEGER out of a value, or report the message as malformed.
fn expect_integer(value : @ber.BerValue) -> Int raise PduError {
  match value {
    @ber.BerValue::Integer(n) => n
    _ => raise PduError::MalformedMessage
  }
}

///|
/// Decode a PDU from the context-class tagged value the BER layer
/// produced.

///|
/// Decode a PDU from a BER value that is already known to be one.
///
/// `Message::decode` uses this internally; it is public because a v3
/// message does not carry a PDU at the top level — it lives inside a
/// scoped PDU, which is decoded on its own (RFC 3412 §6.2).
pub fn Pdu::from_ber(value : @ber.BerValue) -> Pdu raise PduError {
  decode_pdu(value)
}

///|
fn decode_pdu(value : @ber.BerValue) -> Pdu raise PduError {
  let (tag, fields) = match value {
    @ber.BerValue::Tagged(tag, fields) => (tag, fields)
    _ => raise PduError::MalformedMessage
  }
  let pdu_type = PduType::from_tag(tag)
  match pdu_type {
    GetBulkRequest => decode_bulk(fields)
    Trap => decode_trap_v1(fields)
    _ => decode_generic(pdu_type, fields)
  }
}

///|
/// Decode the `{ request-id, error-status, error-index, varbinds }` body
/// shared by GetRequest, GetNextRequest, SetRequest, Response, Inform
/// and TrapV2.
fn decode_generic(
  pdu_type : PduType,
  fields : Array[@ber.BerValue],
) -> Pdu raise PduError {
  if fields.length() != 4 {
    raise PduError::MalformedMessage
  }
  let request_id = expect_integer(fields[0])
  let error_status = ErrorStatus::from_int(expect_integer(fields[1]))
  let error_index = expect_integer(fields[2])
  let varbinds = decode_varbinds(fields[3])
  Generic({ pdu_type, request_id, error_status, error_index, varbinds, })
}

///|
/// Decode a GetBulkRequest body:
/// `{ request-id, non-repeaters, max-repetitions, varbinds }`.
fn decode_bulk(fields : Array[@ber.BerValue]) -> Pdu raise PduError {
  if fields.length() != 4 {
    raise PduError::MalformedBulkPdu
  }
  let request_id = expect_integer(fields[0])
  let non_repeaters = expect_integer(fields[1])
  let max_repetitions = expect_integer(fields[2])
  let varbinds = decode_varbinds(fields[3])
  Bulk({ request_id, non_repeaters, max_repetitions, varbinds, })
}

///|
/// Decode a v1 trap body (RFC 1157 §4.1.6):
/// `{ enterprise, agent-addr, generic-trap, specific-trap, time-stamp,
/// varbinds }`.
fn decode_trap_v1(fields : Array[@ber.BerValue]) -> Pdu raise PduError {
  if fields.length() != 6 {
    raise PduError::MalformedTrap
  }
  let enterprise = match fields[0] {
    @ber.BerValue::ObjectIdentifier(oid) => oid
    _ => raise PduError::MalformedTrap
  }
  let agent_addr = match fields[1] {
    @ber.BerValue::IpAddress(b) => b
    _ => raise PduError::MalformedTrap
  }
  let generic_trap = expect_integer(fields[2])
  let specific_trap = expect_integer(fields[3])
  let time_stamp = match fields[4] {
    @ber.BerValue::TimeTicks(n) => n
    @ber.BerValue::Integer(n) => n.reinterpret_as_uint()
    _ => raise PduError::MalformedTrap
  }
  let varbinds = decode_varbinds(fields[5])
  TrapV1({
    enterprise,
    agent_addr,
    generic_trap,
    specific_trap,
    time_stamp,
    varbinds,
  })
}

///|
/// Decode a SEQUENCE OF `SEQUENCE { name, value }` into var-binds.
fn decode_varbinds(value : @ber.BerValue) -> Array[VarBind] raise PduError {
  let items = match value {
    @ber.BerValue::Sequence(items) => items
    _ => raise PduError::MalformedMessage
  }
  let out : Array[VarBind] = []
  for item in items {
    match item {
      @ber.BerValue::Sequence(pair) =>
        if pair.length() != 2 {
          raise PduError::MalformedMessage
        } else {
          let name = match pair[0] {
            @ber.BerValue::ObjectIdentifier(oid) => oid
            _ => raise PduError::MalformedMessage
          }
          out.push({ name, value: pair[1], })
        }
      _ => raise PduError::MalformedMessage
    }
  }
  out
}
