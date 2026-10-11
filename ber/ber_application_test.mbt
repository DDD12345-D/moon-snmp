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
  // The last value that fits in four octets as a non-negative INTEGER.
  inspect(
    hex(@ber.BerValue::Counter32(0x7FFFFFFF).encode()),
    content="41047fffffff",
  )
  inspect(roundtrip("41047fffffff"), content="41047fffffff")
  // Above that the top bit is set, so the value needs a leading zero to
  // stay non-negative: five octets, not four. net-snmp encodes the
  // saturated ifSpeed of 4294967295 exactly this way.
  inspect(
    hex(@ber.BerValue::Counter32(0x80000000).encode()),
    content="41050080000000",
  )
  inspect(roundtrip("41050080000000"), content="41050080000000")
  inspect(
    hex(@ber.BerValue::Counter32(0xFFFFFFFF).encode()),
    content="410500ffffffff",
  )
  inspect(roundtrip("410500ffffffff"), content="410500ffffffff")
  // A four-octet spelling of the same value is what an agent that does
  // not pad would send; it decodes to the same number and re-encodes in
  // the padded form.
  inspect(roundtrip("4104ffffffff"), content="410500ffffffff")
  // Two leading zeros would be redundant, so that spelling is rejected
  // rather than quietly accepted.
  expect_decode_failure("41060000ffffffff")

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
  // The full 64-bit range needs a leading zero for the same reason: as
  // a non-negative INTEGER, 64 bits of ones would read as minus one.
  inspect(
    hex(@ber.BerValue::Counter64(0xFFFFFFFFFFFFFFFF).encode()),
    content="460900ffffffffffffffff",
  )
  inspect(roundtrip("460900ffffffffffffffff"), content="460900ffffffffffffffff")
  inspect(roundtrip("4608ffffffffffffffff"), content="460900ffffffffffffffff")
  // The largest value that needs no padding.
  inspect(
    hex(@ber.BerValue::Counter64(0x7FFFFFFFFFFFFFFF).encode()),
    content="46087fffffffffffffff",
  )
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
  // Both spellings of the same value decode to it: the padded five-octet
  // form net-snmp sends, and the four-octet form another agent may use.
  match @ber.BerValue::decode(unhex("41050080000000")) {
    Counter32(n) => inspect(n, content="2147483648")
    _ => fail("expected Counter32")
  }
  match @ber.BerValue::decode(unhex("410480000000")) {
    Counter32(n) => inspect(n, content="2147483648")
    _ => fail("expected Counter32")
  }
  match @ber.BerValue::decode(unhex("4304075bcd15")) {
    TimeTicks(n) => inspect(n, content="123456789")
    _ => fail("expected TimeTicks")
  }
  match @ber.BerValue::decode(unhex("460900ffffffffffffffff")) {
    Counter64(n) => inspect(n, content="18446744073709551615")
    _ => fail("expected Counter64")
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
  // IpAddress is exactly four octets, and the counters have a fixed
  // range the content must fit in.
  expect_decode_failure("4003c0a801") // IpAddress with 3 octets
  expect_decode_failure("4005c0a8010101") // IpAddress with 5 octets
  expect_decode_failure("4100") // empty Counter32
  expect_decode_failure("4600") // empty Counter64
  // Leading zeros beyond the one a non-negative value needs are
  // redundant, so the content is not minimally encoded.
  expect_decode_failure("41050000000001")
  expect_decode_failure("42050000000001")
  expect_decode_failure("4309000000000000000001")
  expect_decode_failure("41020001") // the zero was not needed for 1
}

///|
/// Check that decoding `hex_text` is rejected.
///
/// The assertion has to happen *outside* the `try`: a `fail()` inside one
/// is swallowed by the catch-all handler beside it, which is how this
/// test spent several batches asserting nothing at all.
fn expect_decode_failure(hex_text : String) -> Unit raise {
  let decoded : @ber.BerValue? = Some(@ber.BerValue::decode(unhex(hex_text))) catch {
    _ => None
  }
  match decoded {
    None => ()
    Some(value) =>
      fail("expected \{hex_text} to be rejected, decoded to \{Repr(value)}")
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
