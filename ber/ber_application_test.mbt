///|
test "encode and decode IpAddress" {
  // 192.168.1.1 -> 0x40 04 c0 a8 01 01.
  let ip = @ber.BerValue::IpAddress(b"\xc0\xa8\x01\x01")
  inspect(hex(ip.encode()), content="4004c0a80101")
  inspect(roundtrip("4004c0a80101"), content="4004c0a80101")
  inspect(Repr(ip), content="IpAddress(<Bytes: [0xc0, 0xa8, 0x01, 0x01]>)")
}

///|
test "encode and decode Counter32 / Gauge32 / TimeTicks" {
  // A Counter32 of 1: tag 0x41, one octet.
  inspect(hex(@ber.BerValue::Counter32(1).encode()), content="410101")
  // The top bit set must NOT gain a sign octet: 0x80000000 is four
  // octets, not five (this is where treating it as a signed INTEGER
  // would go wrong).
  inspect(
    hex(@ber.BerValue::Counter32(0x80000000).encode()),
    content="410480000000",
  )
  inspect(roundtrip("410480000000"), content="410480000000")
  // The maximum 32-bit counter wraps past 2^31 and still fits.
  inspect(
    hex(@ber.BerValue::Counter32(0xFFFFFFFF).encode()),
    content="4104ffffffff",
  )
  inspect(roundtrip("4104ffffffff"), content="4104ffffffff")

  // Gauge32 and TimeTicks share the shape but keep their own tags.
  inspect(hex(@ber.BerValue::Gauge32(1000).encode()), content="420203e8")
  inspect(
    hex(@ber.BerValue::TimeTicks(123456789).encode()),
    content="4304075bcd15",
  )
  // Zero is a single 0x00 octet.
  inspect(hex(@ber.BerValue::Gauge32(0).encode()), content="420100")
}

///|
test "encode and decode Counter64" {
  inspect(hex(@ber.BerValue::Counter64(1).encode()), content="460101")
  // A value above 2^32 needs five or more octets.
  inspect(
    hex(@ber.BerValue::Counter64(0x1_0000_0000).encode()),
    content="46050100000000",
  )
  inspect(roundtrip("46050100000000"), content="46050100000000")
  // The full 64-bit range stays unsigned.
  inspect(
    hex(@ber.BerValue::Counter64(0xFFFFFFFFFFFFFFFF).encode()),
    content="4608ffffffffffffffff",
  )
  inspect(roundtrip("4608ffffffffffffffff"), content="4608ffffffffffffffff")
}

///|
test "encode and decode Opaque" {
  inspect(
    hex(@ber.BerValue::Opaque(b"\x00\x01\x02").encode()),
    content="4403000102",
  )
  inspect(roundtrip("4403000102"), content="4403000102")
  inspect(hex(@ber.BerValue::Opaque(b"").encode()), content="4400")
}

///|
test "application types decode to the right variant" {
  match @ber.BerValue::decode(unhex("4004c0a80101")) {
    IpAddress(b) =>
      inspect(
        b,
        content=(
          #|b"\xc0\xa8\x01\x01"
        ),
      )
    _ => fail("expected IpAddress")
  }
  match @ber.BerValue::decode(unhex("410480000000")) {
    Counter32(n) => inspect(n, content="2147483648")
    _ => fail("expected Counter32")
  }
  match @ber.BerValue::decode(unhex("4304075bcd15")) {
    TimeTicks(n) => inspect(n, content="123456789")
    _ => fail("expected TimeTicks")
  }
  match @ber.BerValue::decode(unhex("4608ffffffffffffffff")) {
    Counter64(n) => inspect(n, content="18446744073709551615")
    _ => fail("expected Counter64")
  }
  match @ber.BerValue::decode(unhex("4403000102")) {
    Opaque(b) => inspect(b.length(), content="3")
    _ => fail("expected Opaque")
  }
}

///|
test "application types reject malformed widths" {
  let cases : Array[String] = [
    "4003c0a801", // IpAddress with 3 octets
     "4005c0a8010101", // IpAddress with 5 octets
     "41050000000001", // Counter32 wider than 4 octets
     "42050000000001", // Gauge32 wider than 4 octets
     "4309000000000000000001", // Counter64 wider than 8
     "4100", // empty Counter32
     "4600", // empty Counter64
  ]
  for hex_text in cases {
    try {
      let _ = @ber.BerValue::decode(unhex(hex_text))
      fail("expected decode failure for \{hex_text}")
    } catch {
      _ => ()
    }
  }
}

///|
test "the SNMPv2 exceptions decode and round-trip" {
  // RFC 3416 §4.2.1: a v2c agent answers a GET for something it does
  // not have with one of these three context-class primitive tags,
  // zero-length. They are values, not error statuses, so the decoder
  // has to accept them.
  let no_such_object = @ber.BerValue::decode(unhex("8000"))
  inspect(Repr(no_such_object), content="Tagged(128, [])")
  let no_such_instance = @ber.BerValue::decode(unhex("8100"))
  inspect(Repr(no_such_instance), content="Tagged(129, [])")
  let end_of_mib_view = @ber.BerValue::decode(unhex("8200"))
  inspect(Repr(end_of_mib_view), content="Tagged(130, [])")
  // Each one must survive an encode/decode round trip byte for byte.
  inspect(hex(no_such_object.encode()), content="8000")
  inspect(hex(no_such_instance.encode()), content="8100")
  inspect(hex(end_of_mib_view.encode()), content="8200")
}

///|
test "a context-class primitive tag with content is still rejected" {
  // 0x80 with a non-empty body is not one of the exceptions, so it is
  // an unknown primitive tag rather than a silently coerced value.
  try {
    let _ = @ber.BerValue::decode(unhex("800101"))
    fail("expected decode failure")
  } catch {
    @ber.BerError::UnknownTag(_) => ()
    e => fail("expected UnknownTag, got \{Repr(e)}")
  }
}
