///|
/// Encode a var-bind as `SEQUENCE { name, value }` (RFC 3416 §3).
fn encode_varbind(vb : VarBind) -> @ber.BerValue {
  @ber.BerValue::Sequence([@ber.BerValue::ObjectIdentifier(vb.name), vb.value])
}

///|
/// Encode an `Array[VarBind]` as the SEQUENCE OF that goes in every PDU.
fn encode_varbinds(varbinds : Array[VarBind]) -> @ber.BerValue {
  let items : Array[@ber.BerValue] = []
  for vb in varbinds {
    items.push(encode_varbind(vb))
  }
  @ber.BerValue::Sequence(items)
}

///|
/// Encode a PDU: its body fields wrapped in a context-class constructed
/// tag whose value is the PDU type (RFC 3416 §3).
pub fn Pdu::to_ber(self : Pdu) -> @ber.BerValue {
  match self {
    Generic(p) =>
      @ber.BerValue::Tagged(p.pdu_type.tag(), [
        @ber.BerValue::Integer(p.request_id),
        @ber.BerValue::Integer(p.error_status.to_int()),
        @ber.BerValue::Integer(p.error_index),
        encode_varbinds(p.varbinds),
      ])
    Bulk(p) =>
      @ber.BerValue::Tagged(GetBulkRequest.tag(), [
        @ber.BerValue::Integer(p.request_id),
        @ber.BerValue::Integer(p.non_repeaters),
        @ber.BerValue::Integer(p.max_repetitions),
        encode_varbinds(p.varbinds),
      ])
    TrapV1(p) =>
      @ber.BerValue::Tagged(Trap.tag(), [
        @ber.BerValue::ObjectIdentifier(p.enterprise),
        @ber.BerValue::IpAddress(p.agent_addr),
        @ber.BerValue::Integer(p.generic_trap),
        @ber.BerValue::Integer(p.specific_trap),
        @ber.BerValue::TimeTicks(p.time_stamp),
        encode_varbinds(p.varbinds),
      ])
  }
}

///|
/// Encode a full message: `SEQUENCE { version, community, PDU }`
/// (RFC 3416 §7).
pub fn Message::encode(self : Message) -> Bytes {
  @ber.BerValue::Sequence([
    @ber.BerValue::Integer(self.version.to_int()),
    @ber.BerValue::OctetString(self.community),
    self.pdu.to_ber(),
  ]).encode()
}
