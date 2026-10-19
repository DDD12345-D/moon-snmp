///|
/// RFC 7860 moves USM to the SHA-2 family: HMAC-SHA-224/256/384/512,
/// truncated to 16, 24, 32 and 48 octets.
///
/// The RFC has no test vectors of its own — §9.3 says to run RFC 3414
/// appendix A.1's password-to-key with the hash replaced — so the values
/// below were computed from that description by an independent
/// implementation (Python's `hashlib` and `hmac`). A vector this library
/// produced itself would prove only that it is self-consistent.

///|
fn sha2_security(protocol : @snmpv3.AuthProtocol) -> @snmpv3.Security {
  {
    level: @snmpv3.AuthNoPriv,
    user: b"sha2",
    auth_protocol: protocol,
    auth_password: b"maplesyrup",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
}

///|
test "the SHA-2 key localization matches an independent implementation" {
  let protocols = [
    @snmpv3.Sha224,
    @snmpv3.Sha256,
    @snmpv3.Sha384,
    @snmpv3.Sha512,
  ]
  let expected = [
    "0bd8827c6e29f8065e08e09237f177e410f69b90e1782be682075674", "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b",
    "3b298f16164a11184279d5432bf169e2d2a48307de02b3d3f7e2b4f36eb6f0455a53689a3937eea07319a633d2ccba78",
    "22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250adfcffbb0b",
  ]
  let mut i = 0
  while i < protocols.length() {
    let keys = sha2_security(protocols[i]).localize(rfc_engine())
    inspect(hex(keys.auth_key), content=expected[i])
    i = i + 1
  }
}

///|
test "each protocol knows its authenticator and key length" {
  // A message authenticator is not always twelve octets any more, and a
  // decoder that assumes it is would refuse every SHA-2 message.
  inspect(@snmpv3.Sha224.auth_param_length(), content="16")
  inspect(@snmpv3.Sha256.auth_param_length(), content="24")
  inspect(@snmpv3.Sha384.auth_param_length(), content="32")
  inspect(@snmpv3.Sha512.auth_param_length(), content="48")
  inspect(@snmpv3.Md5.auth_param_length(), content="12")
  inspect(@snmpv3.Sha1.auth_param_length(), content="12")
  // The key is the size of the digest the password is stretched with.
  inspect(@snmpv3.Sha224.key_length(), content="28")
  inspect(@snmpv3.Sha256.key_length(), content="32")
  inspect(@snmpv3.Sha384.key_length(), content="48")
  inspect(@snmpv3.Sha512.key_length(), content="64")
}

///|
test "an authenticator is HMAC of the message, truncated" {
  // The same bytes Python's hmac produced, keyed with the localized key
  // above. This is the half the key-derivation test cannot see.
  let message = b"the quick brown fox jumps over the lazy dog"
  let key256 = unhex(
    "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b",
  )
  inspect(
    hex(@snmpv3.auth_digest(@snmpv3.Sha256, key256, message)),
    content="4dfc7d637dd1cd7654dc7f3b650e3fc26b9f422eaadb4434",
  )
  let key512 = unhex(
    "22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250adfcffbb0b",
  )
  inspect(
    hex(@snmpv3.auth_digest(@snmpv3.Sha512, key512, message)),
    content="32724efa8a4bb76c0c4e8fd069ec3a915f03e48755c0dc2d32536d6d9ca21110ea2fc2fca642a1b00775f0db56e1ab3d",
  )
}

///|
test "a SHA-256 message signs, verifies, and rejects the wrong width" {
  let security = sha2_security(@snmpv3.Sha256)
  let keys = security.localize(rfc_engine())
  let message : @snmpv3.V3Message = {
    msg_id: 7,
    msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
    flags: @snmpv3.MsgFlags::of(@snmpv3.AuthNoPriv),
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine: { id: rfc_engine(), boots: 3, time: 100, },
    user: b"sha2",
    // Twenty-four octets, because that is this protocol's authenticator.
    auth_params: Bytes::from_array(Array::make(24, 0)),
    priv_params: b"",
    data: @snmpv3.Plain({
      context_engine_id: rfc_engine(),
      context_name: b"",
      pdu: @pdu.Pdu::request(@pdu.GetRequest, 42, [
        @pdu.VarBind::new(@mib.sys_name(), @ber.BerValue::Null),
      ]),
    }),
  }
  let signed = @snmpv3.sign(message.encode(), @snmpv3.Sha256, keys.auth_key)
  inspect(@snmpv3.verify(signed, @snmpv3.Sha256, keys.auth_key), content="true")
  // The field is 24 octets on the wire, which is what a peer checks.
  let decoded = @snmpv3.V3Message::decode(signed)
  inspect(decoded.auth_params.length(), content="24")
  // Verified as a protocol with a different width, it must not pass: the
  // length check is part of the authentication, not a formality.
  inspect(
    @snmpv3.verify(signed, @snmpv3.Sha512, keys.auth_key),
    content="false",
  )
  // Nor may a byte of the message change.
  let tampered = signed.to_array()
  tampered[tampered.length() - 1] = tampered[tampered.length() - 1] ^ 1
  inspect(
    @snmpv3.verify(Bytes::from_array(tampered), @snmpv3.Sha256, keys.auth_key),
    content="false",
  )
}
