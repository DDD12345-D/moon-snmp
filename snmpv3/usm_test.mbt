///|
/// Tests for the v3 message layer and USM.
///
/// The interesting vectors here are not invented: the key-derivation
/// values come from RFC 3414 appendix A.3, and the message bytes come from
/// a real net-snmp packet dump. Both are the reference implementation
/// stating what the answer is, which is worth far more than a vector this
/// library produced itself.

///|
/// Lowercase hex.
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
fn nibble(b : Byte) -> Int {
  let n = b.to_uint().reinterpret_as_int()
  if n >= 0x30 && n <= 0x39 {
    n - 0x30
  } else if n >= 0x61 && n <= 0x66 {
    n - 0x57
  } else {
    abort("not a hex digit")
  }
}

///|
fn unhex(text : String) -> Bytes {
  let src = @utf8.encode(text)
  let out : Array[Byte] = []
  let mut i = 0
  while i + 1 < src.length() {
    out.push(((nibble(src.at(i)) << 4) | nibble(src.at(i + 1))).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
/// The engine RFC 3414 A.3 localizes keys to.
fn rfc_engine() -> Bytes {
  unhex("000000000000000000000002")
}

///|
test "key localization matches RFC 3414 A.3.1 and A.3.2" {
  // The password is stretched to a megabyte and hashed, and the result is
  // mixed with the engine id. These two values are what the RFC says the
  // answer is, for its own password and engine.
  let md5 : @snmpv3.Security = {
    level: AuthNoPriv,
    user: b"",
    auth_protocol: Md5,
    auth_password: b"maplesyrup",
    priv_protocol: None,
    priv_password: b"",
  }
  let md5_keys = md5.localize(rfc_engine())
  inspect(hex(md5_keys.auth_key), content="526f5eed9fcce26f8964c2930787d82b")

  let sha : @snmpv3.Security = {
    level: AuthNoPriv,
    user: b"",
    auth_protocol: Sha1,
    auth_password: b"maplesyrup",
    priv_protocol: None,
    priv_password: b"",
  }
  let sha_keys = sha.localize(rfc_engine())
  inspect(
    hex(sha_keys.auth_key),
    content="6695febc9288e36282235fc7151f128497b38f3f",
  )
  // The two protocols must not agree: a 16-octet key and a 20-octet key
  // are what make MD5 and SHA sessions different.
  inspect(md5_keys.auth_key.length(), content="16")
  inspect(sha_keys.auth_key.length(), content="20")
}

///|
test "the discovery probe is byte for byte what net-snmp sends" {
  // Captured from `snmpget -v3 -l authPriv -d`. The two variable fields
  // are the message id and the PDU's request id; everything else is fixed
  // by RFC 3412 and RFC 3414, including the empty engine id, the empty
  // user and the empty var-bind list.
  let probe : @snmpv3.V3Message = {
    msg_id: 0x6BB9BEBA,
    msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
    flags: { reportable: true, authenticated: false, encrypted: false, },
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine: @snmpv3.Engine::unknown(),
    user: b"",
    auth_params: b"",
    priv_params: b"",
    data: Plain({
      context_engine_id: b"",
      context_name: b"",
      pdu: @pdu.Pdu::request(@pdu.GetRequest, 0x21508078, []),
    }),
  }
  inspect(
    hex(probe.encode()),
    content="303e020103301102046bb9beba020300ffe30401040201030410300e0400020100020100040004000400301404000400a00e0204215080780201000201003000",
  )
}

///|
test "a real agent's discovery reply decodes" {
  // The answer to the probe above, also from the packet dump: a Report
  // carrying usmStatsUnknownEngineIDs, which is what tells a client the
  // engine id and clock it needs.
  let reply = unhex(
    "3071020103301102046bb9beba020300ffe30401000201030421301f041180001f888072bdcd77dc1ecb6a000000000201010201170400040004003036041180001f888072bdcd77dc1ecb6a000000000400a81f0204215080780201000201003011300f060a2b060106030f01010400410106",
  )
  let message = @snmpv3.V3Message::decode(reply)
  inspect(hex(message.engine.id), content="80001f888072bdcd77dc1ecb6a00000000")
  inspect(message.engine.boots, content="1")
  inspect(message.engine.time, content="23")
  inspect(message.flags.authenticated, content="false")
  inspect(message.flags.reportable, content="false")
  match message.report() {
    Some((oid, count)) => {
      inspect(oid.to_dotted(), content="1.3.6.1.6.3.15.1.1.4.0")
      inspect(count, content="6")
      inspect(@snmpv3.report_meaning(oid), content="the engine id is not known")
    }
    None => fail("expected a Report")
  }
}

///|
test "the flags byte carries the three bits RFC 3412 defines" {
  inspect(
    @snmpv3.MsgFlags::{
      reportable: false,
      authenticated: false,
      encrypted: false,
    }.to_byte(),
    content="0",
  )
  inspect(
    @snmpv3.MsgFlags::{
      reportable: true,
      authenticated: false,
      encrypted: false,
    }.to_byte(),
    content="4",
  )
  // Discovery is the reportable, unauthenticated probe.
  inspect(@snmpv3.MsgFlags::of(NoAuthNoPriv).to_byte(), content="4")
  inspect(@snmpv3.MsgFlags::of(AuthNoPriv).to_byte(), content="5")
  inspect(@snmpv3.MsgFlags::of(AuthPriv).to_byte(), content="7")
  // Reading them back has to give the same level, or a session would
  // treat an encrypted reply as plaintext.
  inspect(@snmpv3.MsgFlags::from_byte(7).level() == AuthPriv, content="true")
  inspect(@snmpv3.MsgFlags::from_byte(5).level() == AuthNoPriv, content="true")
  inspect(
    @snmpv3.MsgFlags::from_byte(4).level() == NoAuthNoPriv,
    content="true",
  )
}

///|
test "signing finds the authenticator field and verifies its own work" {
  // Signing covers the message with its own authenticator blanked, so the
  // field has to be exactly twelve octets and the signature has to survive
  // a round trip through verify.
  let key = unhex("526f5eed9fcce26f8964c2930787d82b")
  let message : @snmpv3.V3Message = {
    msg_id: 7,
    msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
    flags: @snmpv3.MsgFlags::of(AuthNoPriv),
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine: { id: rfc_engine(), boots: 3, time: 100, },
    user: b"e2e-sha",
    auth_params: Bytes::from_array(Array::make(12, 0)),
    priv_params: b"",
    data: Plain({
      context_engine_id: rfc_engine(),
      context_name: b"",
      pdu: @pdu.Pdu::request(@pdu.GetRequest, 42, [
        @pdu.VarBind::new(@mib.sys_name(), @ber.BerValue::Null),
      ]),
    }),
  }
  let signed = @snmpv3.sign(message.encode(), Md5, key)
  inspect(@snmpv3.verify(signed, Md5, key), content="true")
  // A different key must not verify, or the authenticator proves nothing.
  inspect(
    @snmpv3.verify(signed, Md5, unhex("00112233445566778899aabbccddeeff")),
    content="false",
  )
  // Nor must the same message with a byte changed anywhere in it.
  let tampered = signed.to_array()
  tampered[tampered.length() - 1] = tampered[tampered.length() - 1] ^ 1
  inspect(
    @snmpv3.verify(Bytes::from_array(tampered), Md5, key),
    content="false",
  )
}

///|
test "AES privacy round-trips and advances with the salt" {
  let key = unhex("00112233445566778899aabbccddeeff")
  let engine : @snmpv3.Engine = { id: b"", boots: 4, time: 1000, }
  let plaintext = unhex(
    "3029040b80001f8880a32a253f000000000400a018020421508078020100020100300a300806002b06010201",
  )
  let salt = unhex("0000000000000001")
  let ciphertext = @snmpv3.encrypt_aes(plaintext, key, engine, salt)
  inspect(hex(ciphertext) != hex(plaintext), content="true")
  inspect(
    hex(@snmpv3.decrypt_aes(ciphertext, key, engine, salt)),
    content=hex(plaintext),
  )
  // A different salt must give a different keystream, which is the whole
  // reason the salt exists: two messages with the same vector would let
  // anyone recover the difference of their plaintexts.
  let other = @snmpv3.encrypt_aes(
    plaintext,
    key,
    engine,
    unhex("0000000000000002"),
  )
  inspect(hex(other) != hex(ciphertext), content="true")
  // And the clock is part of the vector, so a message built for one
  // engine time does not decrypt under another.
  let later : @snmpv3.Engine = { id: b"", boots: 4, time: 1001, }
  let wrong = @snmpv3.decrypt_aes(ciphertext, key, later, salt)
  inspect(hex(wrong) == hex(plaintext), content="false")
}

///|
test "the AES initial vector is the engine clock followed by the salt" {
  // RFC 3826 §3.1.2.2: the first eight octets are the engine's boots and
  // time as 32-bit big-endian numbers, the last eight are the salt. Those
  // numbers have to match what the USM parameters carried, or the two
  // sides build different vectors and nothing decrypts.
  let engine : @snmpv3.Engine = { id: b"", boots: 1, time: 258, }
  inspect(
    hex(Bytes::from_array(@snmpv3.big_endian(engine.boots, 4))),
    content="00000001",
  )
  inspect(
    hex(Bytes::from_array(@snmpv3.big_endian(engine.time, 4))),
    content="00000102",
  )
}
