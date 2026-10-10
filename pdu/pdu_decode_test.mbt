///|
/// Round-trip and decode tests. The decode side is what proves a real
/// agent's reply is understood; the round-trip proves nothing was lost
/// between the two directions.

///|
test "decode the canonical v2c GetRequest" {
  let message = @pdu.Message::decode(sys_descr_get_request())
  inspect(Repr(message.version), content="V2c")
  inspect(
    message.community,
    content=(
      #|b"public"
    ),
  )
  match message.pdu {
    Generic(p) => {
      inspect(Repr(p.pdu_type), content="GetRequest")
      inspect(p.request_id, content="1246583386") // 0x4a4d5a5a
      inspect(Repr(p.error_status), content="NoError")
      inspect(p.error_index, content="0")
      inspect(p.varbinds.length(), content="1")
      inspect(p.varbinds[0].name.to_dotted(), content="1.3.6.1.2.1.1.1.0")
      inspect(Repr(p.varbinds[0].value), content="Null")
    }
    _ => fail("expected a Generic PDU")
  }
}

///|
test "decode a Response with an OctetString value" {
  let bytes = unhex(
    "303402010104067075626c6963a22702044a4d5a5a0201000201003019301706082b06010201010100040b4c696e757820736e6d7064",
  )
  match @pdu.Message::decode(bytes).pdu {
    Generic(p) => {
      inspect(Repr(p.pdu_type), content="Response")
      match p.varbinds[0].value {
        OctetString(b) =>
          inspect(
            b,
            content=(
              #|b"Linux snmpd"
            ),
          )
        _ => fail("expected OCTET STRING")
      }
    }
    _ => fail("expected a Generic PDU")
  }
}

///|
test "decode a Response with application types" {
  let bytes = unhex(
    "304002010104067075626c6963a23302044a4d5a5a02010002010030253011060a2b060102010202010a01410301e2403010060a2b06010201020201090143020bb8",
  )
  match @pdu.Message::decode(bytes).pdu {
    Generic(p) => {
      inspect(p.varbinds.length(), content="2")
      inspect(p.varbinds[0].name.to_dotted(), content="1.3.6.1.2.1.2.2.1.10.1")
      match p.varbinds[0].value {
        Counter32(n) => inspect(n, content="123456")
        _ => fail("expected Counter32")
      }
      inspect(p.varbinds[1].name.to_dotted(), content="1.3.6.1.2.1.2.2.1.9.1")
      match p.varbinds[1].value {
        TimeTicks(n) => inspect(n, content="3000")
        _ => fail("expected TimeTicks")
      }
    }
    _ => fail("expected a Generic PDU")
  }
}

///|
test "decode an error status and index" {
  let bytes = unhex(
    "302902010104067075626c6963a21c02044a4d5a5a020102020101300e300c06082b060102010101000500",
  )
  match @pdu.Message::decode(bytes).pdu {
    Generic(p) => {
      inspect(Repr(p.error_status), content="NoSuchName")
      inspect(p.error_index, content="1")
    }
    _ => fail("expected a Generic PDU")
  }
}

///|
test "decode a GetBulkRequest into its Bulk shape" {
  let bytes = unhex(
    "302902010104067075626c6963a51c02045566778802010002010a300e300c06082b060102010202010500",
  )
  match @pdu.Message::decode(bytes).pdu {
    Bulk(p) => {
      inspect(p.request_id, content="1432778632") // 0x55667788
      inspect(p.non_repeaters, content="0")
      inspect(p.max_repetitions, content="10")
      inspect(p.varbinds.length(), content="1")
    }
    _ => fail("expected a Bulk PDU")
  }
}

///|
test "decode a v1 trap into its own shape" {
  let bytes = unhex(
    "303802010004067075626c6963a42b06072b06010401bf084004c0a8010102010602010143021d4c3010300e06082b0601020101010004027570",
  )
  let message = @pdu.Message::decode(bytes)
  inspect(Repr(message.version), content="V1")
  match message.pdu {
    TrapV1(p) => {
      inspect(p.enterprise.to_dotted(), content="1.3.6.1.4.1.8072")
      inspect(
        p.agent_addr,
        content=(
          #|b"\xc0\xa8\x01\x01"
        ),
      )
      inspect(p.generic_trap, content="6")
      inspect(p.specific_trap, content="1")
      inspect(p.time_stamp, content="7500")
      match p.varbinds[0].value {
        OctetString(b) =>
          inspect(
            b,
            content=(
              #|b"up"
            ),
          )
        _ => fail("expected OCTET STRING")
      }
    }
    _ => fail("expected a v1 trap")
  }
}

///|
test "every golden vector survives a round-trip" {
  let vectors = [
    "302902010104067075626c6963a01c02044a4d5a5a020100020100300e300c06082b060102010101000500",
    "302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500",
    "302902010104067075626c6963a11c020411223344020100020100300e300c06082b060102010101000500",
    "302902010104067075626c6963a51c02045566778802010002010a300e300c06082b060102010202010500",
    "303402010104067075626c6963a22702044a4d5a5a0201000201003019301706082b06010201010100040b4c696e757820736e6d7064",
    "304002010104067075626c6963a23302044a4d5a5a02010002010030253011060a2b060102010202010a01410301e2403010060a2b06010201020201090143020bb8",
    "302902010104067075626c6963a21c02044a4d5a5a020102020101300e300c06082b060102010101000500",
    "303802010004067075626c6963a42b06072b06010401bf084004c0a8010102010602010143021d4c3010300e06082b0601020101010004027570",
  ]
  for hex_text in vectors {
    let bytes = unhex(hex_text)
    let decoded = @pdu.Message::decode(bytes)
    inspect(hex(decoded.encode()), content=hex_text)
  }
}

///|
test "messages with several varbinds round-trip" {
  let varbinds : Array[@pdu.VarBind] = []
  for i in 0..<5 {
    varbinds.push(
      @pdu.VarBind::new(
        @oid.Oid::parse("1.3.6.1.2.1.1.0"),
        @ber.BerValue::Integer(i),
      ),
    )
  }
  let message = @pdu.Message::new(
    @pdu.V2c,
    b"public",
    @pdu.Pdu::request(@pdu.SetRequest, 99, varbinds),
  )
  let decoded = @pdu.Message::decode(message.encode())
  inspect(decoded.pdu.varbinds().length(), content="5")
  inspect(Repr(decoded.pdu.pdu_type()), content="SetRequest")
}

///|
test "decode rejects malformed messages" {
  let cases : Array[String] = [
    // Outer value is not a SEQUENCE.
    "020100",
    // Only two fields where three are required.
     "301202010104067075626c6963",
    // Version 2 was never assigned.
     "301602010204067075626c6963a007020100020100020100",
    // Unknown PDU tag 0xaf.
     "302902010104067075626c6963af1c02044a4d5a5a020100020100300e300c06082b060102010101000500",
    // A PDU whose body has the wrong field count.
     "301902010104067075626c6963a00c02044a4d5a5a020100020100",
    // A varbind whose pair has three elements instead of two.
     "302a02010104067075626c6963a01c02044a4d5a5a020100020100300f300d06052b0601020101050100",
    // An error-status above 18.
     "302902010104067075626c6963a21c02044a4d5a5a020113020101300e300c06082b060102010101000500",
  ]
  for hex_text in cases {
    try {
      let _ = @pdu.Message::decode(unhex(hex_text))
      fail("expected decode failure for \{hex_text}")
    } catch {
      _ => ()
    }
  }
}
