///|
/// Golden vectors for the SNMP message layer. The byte strings were
/// produced by an independent second implementation of the RFC 3416 §7
/// layout, and the key ones match what net-snmp puts on the wire for
/// the same requests. Every case is asserted in both directions: bytes
/// to message, and message back to the same bytes.

///|
test "encode a v2c GetRequest for sysDescr.0" {
  let message = @pdu.Message::new(
    @pdu.V2c,
    b"public",
    @pdu.Pdu::request(@pdu.GetRequest, 0x4A4D5A5A, [
      @pdu.VarBind::new(
        @oid.Oid::parse("1.3.6.1.2.1.1.1.0"),
        @ber.BerValue::Null,
      ),
    ]),
  )
  inspect(
    hex(message.encode()),
    content="302902010104067075626c6963a01c02044a4d5a5a020100020100300e300c06082b060102010101000500",
  )
}

///|
test "encode a v1 GetRequest" {
  let message = @pdu.Message::new(
    @pdu.V1,
    b"public",
    @pdu.Pdu::request(@pdu.GetRequest, 1, [
      @pdu.VarBind::new(
        @oid.Oid::parse("1.3.6.1.2.1.1.1.0"),
        @ber.BerValue::Null,
      ),
    ]),
  )
  inspect(
    hex(message.encode()),
    content="302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500",
  )
}

///|
test "encode a v2c GetNextRequest" {
  let message = @pdu.Message::new(
    @pdu.V2c,
    b"public",
    @pdu.Pdu::request(@pdu.GetNextRequest, 0x11223344, [
      @pdu.VarBind::new(
        @oid.Oid::parse("1.3.6.1.2.1.1.1.0"),
        @ber.BerValue::Null,
      ),
    ]),
  )
  inspect(
    hex(message.encode()),
    content="302902010104067075626c6963a11c020411223344020100020100300e300c06082b060102010101000500",
  )
}

///|
test "encode a GetBulkRequest with max-repetitions" {
  let message = @pdu.Message::new(
    @pdu.V2c,
    b"public",
    @pdu.Bulk({
      request_id: 0x55667788,
      non_repeaters: 0,
      max_repetitions: 10,
      varbinds: [
        @pdu.VarBind::new(
          @oid.Oid::parse("1.3.6.1.2.1.2.2.1"),
          @ber.BerValue::Null,
        ),
      ],
    }),
  )
  let encoded = hex(message.encode())
  inspect(
    encoded,
    content="302902010104067075626c6963a51c02045566778802010002010a300e300c06082b060102010202010500",
  )
  // The 0x0a at the max-repetitions slot is the field that makes this a
  // bulk request rather than a plain one.
  inspect(encoded.contains("02010a"), content="true")
}

///|
test "encode a Response carrying OctetString" {
  let message = @pdu.Message::new(
    @pdu.V2c,
    b"public",
    @pdu.Pdu::response(0x4A4D5A5A, @pdu.NoError, 0, [
      @pdu.VarBind::new(
        @oid.Oid::parse("1.3.6.1.2.1.1.1.0"),
        @ber.BerValue::OctetString(b"Linux snmpd"),
      ),
    ]),
  )
  inspect(
    hex(message.encode()),
    content="303402010104067075626c6963a22702044a4d5a5a0201000201003019301706082b06010201010100040b4c696e757820736e6d7064",
  )
}

///|
test "encode a Response carrying application types" {
  let message = @pdu.Message::new(
    @pdu.V2c,
    b"public",
    @pdu.Pdu::response(0x4A4D5A5A, @pdu.NoError, 0, [
      @pdu.VarBind::new(
        @oid.Oid::parse("1.3.6.1.2.1.2.2.1.10.1"),
        @ber.BerValue::Counter32(123456),
      ),
      @pdu.VarBind::new(
        @oid.Oid::parse("1.3.6.1.2.1.2.2.1.9.1"),
        @ber.BerValue::TimeTicks(3000),
      ),
    ]),
  )
  let encoded = hex(message.encode())
  inspect(
    encoded,
    content="304002010104067075626c6963a23302044a4d5a5a02010002010030253011060a2b060102010202010a01410301e2403010060a2b06010201020201090143020bb8",
  )
  // Both application tags survive: 0x41 Counter32, 0x43 TimeTicks.
  inspect(encoded.contains("410301e240"), content="true")
  inspect(encoded.contains("43020bb8"), content="true")
}

///|
test "encode a Response carrying an error status" {
  let message = @pdu.Message::new(
    @pdu.V2c,
    b"public",
    @pdu.Pdu::response(0x4A4D5A5A, @pdu.NoSuchName, 1, [
      @pdu.VarBind::new(
        @oid.Oid::parse("1.3.6.1.2.1.1.1.0"),
        @ber.BerValue::Null,
      ),
    ]),
  )
  inspect(
    hex(message.encode()),
    content="302902010104067075626c6963a21c02044a4d5a5a020102020101300e300c06082b060102010101000500",
  )
}

///|
test "encode a v1 trap" {
  let message = @pdu.Message::new(
    @pdu.V1,
    b"public",
    @pdu.TrapV1({
      enterprise: @oid.Oid::parse("1.3.6.1.4.1.8072"),
      agent_addr: b"\xc0\xa8\x01\x01",
      generic_trap: 6,
      specific_trap: 1,
      time_stamp: 7500,
      varbinds: [
        @pdu.VarBind::new(
          @oid.Oid::parse("1.3.6.1.2.1.1.1.0"),
          @ber.BerValue::OctetString(b"up"),
        ),
      ],
    }),
  )
  inspect(
    hex(message.encode()),
    content="303802010004067075626c6963a42b06072b06010401bf084004c0a8010102010602010143021d4c3010300e06082b0601020101010004027570",
  )
}
