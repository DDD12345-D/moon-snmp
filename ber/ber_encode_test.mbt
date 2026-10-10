///|
/// Shared helpers for the BER blackbox tests. `_test.mbt` files in one
/// package share scope, so both suites can use these.

///|
/// Render bytes as lowercase hex. Golden vectors are written as hex
/// strings because `inspect` prints printable bytes as characters
/// (0x2b as `+`), which makes raw byte snapshots hard to read.
fn hex(bytes : Bytes) -> String {
  let digits = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
  ]
  let out : Array[String] = []
  for i in 0..<bytes.length() {
    let b = bytes.at(i).to_uint().reinterpret_as_int()
    out.push(digits[b >> 4])
    out.push(digits[b & 0xF])
  }
  out.join("")
}

///|
/// Parse a lowercase hex string into bytes.
fn unhex(hex_text : String) -> Bytes {
  let bytes = @utf8.encode(hex_text)
  let out : Array[Byte] = []
  let mut i = 0
  while i + 1 < bytes.length() {
    out.push(((nibble(bytes.at(i)) << 4) | nibble(bytes.at(i + 1))).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
fn nibble(c : Byte) -> Int {
  let n = c.to_uint().reinterpret_as_int()
  if n >= 0x30 && n <= 0x39 {
    n - 0x30
  } else if n >= 0x61 && n <= 0x66 {
    n - 0x61 + 10
  } else {
    0
  }
}

///|
/// Decode a hex vector, re-encode it and return the hex again. A no-op
/// result is the encoder/decoder round-trip the spec promises.
fn roundtrip(hex_text : String) -> String raise {
  let value = @ber.BerValue::decode(unhex(hex_text))
  hex(value.encode())
}

///|
test "encode INTEGER covers sign and minimality" {
  // Golden vectors from X.690 §8.3 and RFC 3416.
  inspect(hex(@ber.BerValue::Integer(0).encode()), content="020100")
  inspect(hex(@ber.BerValue::Integer(127).encode()), content="02017f")
  // 128 needs a leading 0x00 so the sign bit stays clear.
  inspect(hex(@ber.BerValue::Integer(128).encode()), content="02020080")
  inspect(hex(@ber.BerValue::Integer(256).encode()), content="02020100")
  // -1 is a single 0xFF octet, not 0xFFFF.
  inspect(hex(@ber.BerValue::Integer(-1).encode()), content="0201ff")
  inspect(hex(@ber.BerValue::Integer(-128).encode()), content="020180")
  // -129 needs a leading 0xFF to keep the sign.
  inspect(hex(@ber.BerValue::Integer(-129).encode()), content="0202ff7f")
  inspect(hex(@ber.BerValue::Integer(-256).encode()), content="0202ff00")
  // The extremes of the signed 32-bit range SNMP uses.
  inspect(
    hex(@ber.BerValue::Integer(2147483647).encode()),
    content="02047fffffff",
  )
  inspect(
    hex(@ber.BerValue::Integer(-2147483648).encode()),
    content="020480000000",
  )
}

///|
test "encode OCTET STRING" {
  inspect(
    hex(@ber.BerValue::OctetString(b"\x41\x42\x43").encode()),
    content="0403414243",
  )
  inspect(hex(@ber.BerValue::OctetString(b"").encode()), content="0400")
}

///|
test "encode NULL" {
  inspect(hex(@ber.BerValue::Null.encode()), content="0500")
}

///|
test "encode OID" {
  // sysDescr.0 = 1.3.6.1.2.1.1.1.0 (the canonical Net-SNMP vector).
  inspect(
    hex(
      @ber.BerValue::ObjectIdentifier(@oid.Oid::parse("1.3.6.1.2.1.1.1.0")).encode(),
    ),
    content="06082b06010201010100",
  )
  // 2.100.3 packs the root pair as 40*2 + 100 = 180 -> two base-128 octets.
  inspect(
    hex(@ber.BerValue::ObjectIdentifier(@oid.Oid::parse("2.100.3")).encode()),
    content="0603813403",
  )
  // A multi-octet subidentifier: 1.3.6.1.4.1.2021.10.1.3.1 (UCD-SNMP),
  // where 2021 = 0x7E5 needs two base-128 octets (0x8F 0x65).
  inspect(
    hex(
      @ber.BerValue::ObjectIdentifier(
        @oid.Oid::parse("1.3.6.1.4.1.2021.10.1.3.1"),
      ).encode(),
    ),
    content="060b2b060104018f650a010301",
  )
}

///|
test "encode SEQUENCE nests values" {
  let seq = @ber.BerValue::Sequence([
    @ber.BerValue::Integer(1),
    @ber.BerValue::OctetString(b"\x41"),
  ])
  inspect(hex(seq.encode()), content="3006020101040141")
  // An empty SEQUENCE is legal.
  inspect(hex(@ber.BerValue::Sequence([]).encode()), content="3000")
}

///|
test "encode uses the long length form beyond 127 octets" {
  let payload = Bytes::make(128, b'\x41')
  let encoded = hex(@ber.BerValue::OctetString(payload).encode())
  // 0x81 0x80 is the two-octet long form for length 128.
  inspect(encoded.length(), content="262") // 4 header + 256 hex digits
  inspect(encoded[:6].to_owned(), content="048180")

  // A 300-octet body: 0x82 0x01 0x2C.
  let big = hex(@ber.BerValue::OctetString(Bytes::make(300, b'\x00')).encode())
  inspect(big[:8].to_owned(), content="0482012c")
}
