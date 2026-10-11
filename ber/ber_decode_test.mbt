///|
test "decode INTEGER" {
  // Values are compared through their repr so tests read as "what went
  // in comes back out" rather than depending on a Show impl.
  let check = fn(hex_text : String, expected : String) raise {
    let value = @ber.BerValue::decode(unhex(hex_text))
    inspect(Repr(value), content=expected)
  }
  check("020100", "Integer(0)")
  check("02017f", "Integer(127)")
  check("02020080", "Integer(128)")
  check("0201ff", "Integer(-1)")
  check("020180", "Integer(-128)")
  check("0202ff7f", "Integer(-129)")
  check("02047fffffff", "Integer(2147483647)")
  check("020480000000", "Integer(-2147483648)")
}

///|
test "decode OCTET STRING and NULL" {
  let abc = @ber.BerValue::decode(unhex("0403414243"))
  match abc {
    OctetString(b) =>
      inspect(
        b,
        content=(
          #|b"ABC"
        ),
      )
    _ => fail("expected OCTET STRING")
  }
  let empty = @ber.BerValue::decode(unhex("0400"))
  match empty {
    OctetString(b) => inspect(b.length(), content="0")
    _ => fail("expected empty OCTET STRING")
  }
  inspect(Repr(@ber.BerValue::decode(unhex("0500"))), content="Null")
}

///|
test "decode OID" {
  let sys_descr = @ber.BerValue::decode(unhex("06082b06010201010100"))
  match sys_descr {
    ObjectIdentifier(oid) =>
      inspect(oid.to_dotted(), content="1.3.6.1.2.1.1.1.0")
    _ => fail("expected OID")
  }
  let uc_davis = @ber.BerValue::decode(unhex("060b2b060104018f650a010301"))
  match uc_davis {
    ObjectIdentifier(oid) =>
      inspect(oid.to_dotted(), content="1.3.6.1.4.1.2021.10.1.3.1")
    _ => fail("expected OID")
  }
}

///|
test "decode SEQUENCE, including nesting" {
  let seq = @ber.BerValue::decode(unhex("3006020101040141"))
  inspect(
    Repr(seq),
    content="Sequence([Integer(1), OctetString(<Bytes: [0x41]>)])",
  )
  // SEQUENCE { SEQUENCE { INTEGER 1 } }
  let nested = @ber.BerValue::decode(unhex("30053003020101"))
  match nested {
    Sequence(outer) => {
      inspect(outer.length(), content="1")
      match outer[0] {
        Sequence(inner) => {
          inspect(inner.length(), content="1")
          match inner[0] {
            Integer(n) => inspect(n, content="1")
            _ => fail("expected inner INTEGER")
          }
        }
        _ => fail("expected inner SEQUENCE")
      }
    }
    _ => fail("expected outer SEQUENCE")
  }
}

///|
test "decode handles the long length form" {
  let short = roundtrip("048180" + "41".repeat(128))
  inspect(short[:6].to_owned(), content="048180")

  // 365-octet payload uses the 0x82 form.
  let big = roundtrip("0482016d" + "41".repeat(365))
  inspect(big[:8].to_owned(), content="0482016d")
}

///|
test "decode rejects malformed input" {
  let cases : Array[String] = [
    "", // no tag
     "02", // tag only, no length
     "020201", // truncated content
     "02010000", // trailing byte
     "0405414243", // length past the end
     "0900", // unknown tag
     "300000", // trailing byte after empty SEQUENCE
     "060180", // OID ending on a continuation bit
     "050100", // NULL with content
     "02050000000000", // INTEGER wider than 32 bits
     "04800000", // indefinite length (forbidden by SNMP)
     "04850000000001", // length field longer than four octets
  ]
  for hex_text in cases {
    expect_decode_failure(hex_text)
  }
}
