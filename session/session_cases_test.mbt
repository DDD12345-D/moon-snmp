///|
/// Build a Response message the way an agent would put it on the wire.
fn reply_message(
  request_id : Int,
  varbinds : Array[@pdu.VarBind],
  error_status : @pdu.ErrorStatus,
  error_index : Int,
) -> Bytes {
  @pdu.Message::new(
    @pdu.V2c,
    b"public",
    @pdu.Pdu::response(request_id, error_status, error_index, varbinds),
  ).encode()
}

///|
/// Parse an OID written as `"1, 3, 6, 1"` or `"1.3.6.1"`. Tests read
/// better with the literal arcs spelled out than with an array of
/// numbers, but `Oid::parse` only takes the dotted form.
///
/// Aborts on a typo in the literal rather than threading `raise`
/// through every call site: `test` blocks cannot declare `raise`.
fn oid(text : String) -> @oid.Oid {
  let out : Array[String] = []
  let mut current = ""
  for c in text {
    if c == ',' || c == ' ' {
      if current != "" {
        out.push(current)
        current = ""
      }
    } else {
      current = current + c.to_string()
    }
  }
  if current != "" {
    out.push(current)
  }
  @oid.Oid::parse(out.join(".")) catch {
    _ => abort("bad OID literal in test: \{text}")
  }
}

///|
/// A v2c Response for one OID carrying a UTF-8 string value.
fn reply_octet_string(
  request_id : Int,
  dotted : String,
  text : String,
) -> Bytes {
  reply_message(
    request_id,
    [
      @pdu.VarBind::new(
        oid(dotted),
        @ber.BerValue::OctetString(@utf8.encode(text)),
      ),
    ],
    @pdu.NoError,
    0,
  )
}

///|
/// A session pointed at a made-up agent with the given script.
fn scripted(
  script : Array[Script],
  retries : Int,
) -> (@session.Session[FakeTransport], FakeTransport) {
  let fake = FakeTransport::new(script)
  let session = @session.Session::new(
    fake,
    "127.0.0.1",
    16161,
    @pdu.V2c,
    b"public",
    50,
    retries,
    1000,
  )
  (session, fake)
}

///|
test "request ids advance and wrap inside the signed 32-bit range" {
  let fake = FakeTransport::new([])
  let session = @session.Session::new(
    fake,
    "h",
    1,
    @pdu.V2c,
    b"c",
    10,
    0,
    2147483645,
  )
  inspect(session.take_request_id(), content="2147483645")
  inspect(session.take_request_id(), content="2147483646")
  // 2147483646 is the last id below the wrap point.
  inspect(session.take_request_id(), content="2147483647")
  // Wrapped back to 1 rather than overflowing into a negative id.
  inspect(session.take_request_id(), content="1")
  inspect(session.take_request_id(), content="2")
}

///|
test "addr renders host and port" {
  let (session, _) = scripted([], 0)
  inspect(session.addr(), content="127.0.0.1:16161")
}

///|
test "get sends one datagram to the session address and returns the value" {
  let (session, fake) = scripted(
    [Reply(reply_octet_string(1000, "1, 3, 6, 1, 2, 1, 1, 1, 0", "hello"))],
    0,
  )
  let vb = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
  inspect(vb.name.to_dotted(), content="1.3.6.1.2.1.1.1.0")
  match vb.value {
    @ber.BerValue::OctetString(bytes) => inspect(bytes, content="b\"hello\"")
    _ => fail("expected an OctetString")
  }
  inspect(fake.sent.length(), content="1")
  inspect(fake.sent_hosts[0], content="127.0.0.1")
  inspect(fake.sent_ports[0], content="16161")
}

///|
test "the request id on the wire is the one the session allocated" {
  let (session, fake) = scripted(
    [Reply(reply_octet_string(1000, "1, 3, 6, 1, 2, 1, 1, 1, 0", "hello"))],
    0,
  )
  let _ = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
  let sent = @pdu.Message::decode(fake.sent[0])
  inspect(sent.pdu.request_id(), content="1000")
  inspect(sent.community, content="b\"public\"")
  match sent.version {
    @pdu.V2c => ()
    v => fail("expected V2c, got \{v.to_int()}")
  }
}

///|
test "a stray reply with the wrong request id is skipped, not returned" {
  // First datagram belongs to somebody else's request; the second one is
  // ours. A session that trusted the first would parse the wrong answer.
  let (session, fake) = scripted(
    [
      Reply(reply_octet_string(999, "1, 3, 6, 1, 2, 1, 1, 1, 0", "theirs")),
      Reply(reply_octet_string(1000, "1, 3, 6, 1, 2, 1, 1, 1, 0", "ours")),
    ],
    0,
  )
  let vb = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
  match vb.value {
    @ber.BerValue::OctetString(bytes) => inspect(bytes, content="b\"ours\"")
    _ => fail("expected an OctetString")
  }
  // Only one datagram was sent: the mismatch was absorbed in the same
  // attempt window rather than triggering a retransmission.
  inspect(fake.sent.length(), content="1")
}

///|
test "a wrong-community agent is silent, so the session retries then gives up" {
  // RFC 1157 §4.1: a bad community is dropped without a reply. Three
  // timeouts with retries = 2 means three sends.
  let (session, fake) = scripted([Timeout, Timeout, Timeout], 2)
  try {
    let _ = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
    fail("expected NoResponse")
  } catch {
    @session.SnmpError::NoResponse => ()
    e => fail("expected NoResponse, got \{Repr(e)}")
  }
  inspect(fake.sent.length(), content="3")
}

///|
test "a timeout on the first attempt can still be rescued by a retry" {
  let (session, fake) = scripted(
    [
      Timeout,
      Reply(
        reply_octet_string(1000, "1, 3, 6, 1, 2, 1, 1, 1, 0", "second time"),
      ),
    ],
    1,
  )
  let vb = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
  match vb.value {
    @ber.BerValue::OctetString(bytes) =>
      inspect(bytes, content="b\"second time\"")
    _ => fail("expected an OctetString")
  }
  inspect(fake.sent.length(), content="2")
}

///|
test "with retries disabled a single timeout is final" {
  let (session, fake) = scripted([Timeout], 0)
  try {
    let _ = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
    fail("expected NoResponse")
  } catch {
    @session.SnmpError::NoResponse => ()
    e => fail("expected NoResponse, got \{Repr(e)}")
  }
  inspect(fake.sent.length(), content="1")
}

///|
test "an agent error status surfaces with its index, not as an empty varbind" {
  // noSuchName on the first varbind, the classic "this OID is not here".
  let (session, _) = scripted(
    [
      Reply(
        reply_message(
          1000,
          [
            @pdu.VarBind::new(
              oid("1, 3, 6, 1, 2, 1, 1, 99, 0"),
              @ber.BerValue::Null,
            ),
          ],
          @pdu.NoSuchName,
          1,
        ),
      ),
    ],
    0,
  )
  try {
    let _ = session.get(oid("1, 3, 6, 1, 2, 1, 1, 99, 0"))
    fail("expected AgentError")
  } catch {
    @session.SnmpError::AgentError(status, index) => {
      inspect(status.to_int(), content="2")
      inspect(index, content="1")
    }
    e => fail("expected AgentError, got \{Repr(e)}")
  }
}

///|
test "v2c noSuchObject is a value, not an error status" {
  // Under v2c a missing OID comes back as a varbind holding
  // noSuchObject, with error-status 0. The session must hand it through.
  let (session, _) = scripted(
    [
      Reply(
        reply_message(
          1000,
          [
            @pdu.VarBind::new(
              oid("1, 3, 6, 1, 2, 1, 1, 99, 0"),
              @ber.BerValue::Tagged(0x80, []),
            ),
          ],
          @pdu.NoError,
          0,
        ),
      ),
    ],
    0,
  )
  let vb = session.get(oid("1, 3, 6, 1, 2, 1, 1, 99, 0"))
  match vb.value {
    @ber.BerValue::Tagged(tag, _) => inspect(tag, content="128")
    _ => fail("expected a noSuchObject Tagged value")
  }
}

///|
test "a truncated datagram is reported as Malformed" {
  let (session, _) = scripted([Reply(b"\x30\x82\xff")], 0)
  try {
    let _ = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
    fail("expected Malformed")
  } catch {
    @session.SnmpError::Malformed(_) => ()
    e => fail("expected Malformed, got \{Repr(e)}")
  }
}

///|
test "get_many puts every OID in one request" {
  let (session, fake) = scripted(
    [
      Reply(
        reply_message(
          1000,
          [
            @pdu.VarBind::new(
              oid("1, 3, 6, 1, 2, 1, 1, 1, 0"),
              @ber.BerValue::OctetString(b"Linux"),
            ),
            @pdu.VarBind::new(
              oid("1, 3, 6, 1, 2, 1, 1, 5, 0"),
              @ber.BerValue::OctetString(b"moon-snmp-test"),
            ),
          ],
          @pdu.NoError,
          0,
        ),
      ),
    ],
    0,
  )
  let vbs = session.get_many([
    oid("1, 3, 6, 1, 2, 1, 1, 1, 0"),
    oid("1, 3, 6, 1, 2, 1, 1, 5, 0"),
  ])
  inspect(vbs.length(), content="2")
  inspect(fake.sent.length(), content="1")
  let sent = @pdu.Message::decode(fake.sent[0])
  inspect(sent.pdu.pdu_type().tag(), content="160")
  inspect(sent.pdu.varbinds().length(), content="2")
}

///|
test "get_next asks for the successor and hands back whatever comes" {
  let (session, fake) = scripted(
    [
      Reply(
        reply_message(
          1000,
          [
            @pdu.VarBind::new(
              oid("1, 3, 6, 1, 2, 1, 1, 2, 0"),
              @ber.BerValue::ObjectIdentifier(
                oid("1, 3, 6, 1, 4, 1, 8072, 3, 2, 10"),
              ),
            ),
          ],
          @pdu.NoError,
          0,
        ),
      ),
    ],
    0,
  )
  let vb = session.get_next(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
  inspect(vb.name.to_dotted(), content="1.3.6.1.2.1.1.2.0")
  let sent = @pdu.Message::decode(fake.sent[0])
  inspect(sent.pdu.pdu_type().tag(), content="161")
}

///|
test "get_bulk carries non-repeaters and max-repetitions in the PDU body" {
  let (session, fake) = scripted(
    [
      Reply(
        reply_message(
          1000,
          [
            @pdu.VarBind::new(
              oid("1, 3, 6, 1, 2, 1, 1, 1, 0"),
              @ber.BerValue::OctetString(b"Linux"),
            ),
          ],
          @pdu.NoError,
          0,
        ),
      ),
    ],
    0,
  )
  let vbs = session.get_bulk([oid("1, 3, 6, 1, 2, 1")], 0, 10)
  inspect(vbs.length(), content="1")
  let sent = @pdu.Message::decode(fake.sent[0])
  inspect(sent.pdu.pdu_type().tag(), content="165")
  match sent.pdu {
    @pdu.Bulk(p) => {
      inspect(p.non_repeaters, content="0")
      inspect(p.max_repetitions, content="10")
    }
    _ => fail("expected a BulkPdu")
  }
}

///|
test "set sends the value as given" {
  let (session, fake) = scripted(
    [
      Reply(
        reply_message(
          1000,
          [
            @pdu.VarBind::new(
              oid("1, 3, 6, 1, 2, 1, 1, 5, 0"),
              @ber.BerValue::OctetString(b"new-name"),
            ),
          ],
          @pdu.NoError,
          0,
        ),
      ),
    ],
    0,
  )
  let vbs = session.set(
    oid("1, 3, 6, 1, 2, 1, 1, 5, 0"),
    @ber.BerValue::OctetString(b"new-name"),
  )
  inspect(vbs.length(), content="1")
  let sent = @pdu.Message::decode(fake.sent[0])
  inspect(sent.pdu.pdu_type().tag(), content="163")
  match sent.pdu.varbinds()[0].value {
    @ber.BerValue::OctetString(bytes) => inspect(bytes, content="b\"new-name\"")
    _ => fail("expected an OctetString")
  }
}

///|
test "consecutive requests use different ids" {
  let (session, fake) = scripted(
    [
      Reply(reply_octet_string(1000, "1, 3, 6, 1, 2, 1, 1, 1, 0", "a")),
      Reply(reply_octet_string(1001, "1, 3, 6, 1, 2, 1, 1, 5, 0", "b")),
    ],
    0,
  )
  let _ = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
  let _ = session.get(oid("1, 3, 6, 1, 2, 1, 1, 5, 0"))
  let first = @pdu.Message::decode(fake.sent[0])
  let second = @pdu.Message::decode(fake.sent[1])
  inspect(first.pdu.request_id(), content="1000")
  inspect(second.pdu.request_id(), content="1001")
}

///|
test "a send failure is reported as NoResponse rather than hanging" {
  let (session, _) = scripted([SendFailure], 0)
  try {
    let _ = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
    fail("expected NoResponse")
  } catch {
    @session.SnmpError::NoResponse => ()
    e => fail("expected NoResponse, got \{Repr(e)}")
  }
}

///|
test "an unsolicited v1 trap is never mistaken for a reply" {
  // A v1 trap carries no request id, so it can never match an
  // outstanding request. The session must discard it rather than parse
  // the trap body as if it were the answer to a GET.
  let trap = @pdu.Message::new(
    @pdu.V1,
    b"public",
    @pdu.Pdu::TrapV1({
      enterprise: oid("1, 3, 6, 1, 4, 1, 8072"),
      agent_addr: b"\x7f\x00\x00\x01",
      generic_trap: 6,
      specific_trap: 1,
      time_stamp: 42,
      varbinds: [],
    }),
  )
  let (session, fake) = scripted([Reply(trap.encode()), Timeout], 0)
  try {
    let _ = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
    fail("expected NoResponse")
  } catch {
    // The trap is dropped in the same window; the window then times out.
    @session.SnmpError::NoResponse => ()
    e => fail("expected NoResponse, got \{Repr(e)}")
  }
  inspect(fake.sent.length(), content="1")
}

///|
test "a response with a different varbind count than the request is refused by get" {
  let (session, _) = scripted(
    [
      Reply(
        reply_message(
          1000,
          [
            @pdu.VarBind::new(
              oid("1, 3, 6, 1, 2, 1, 1, 1, 0"),
              @ber.BerValue::OctetString(b"a"),
            ),
            @pdu.VarBind::new(
              oid("1, 3, 6, 1, 2, 1, 1, 5, 0"),
              @ber.BerValue::OctetString(b"b"),
            ),
          ],
          @pdu.NoError,
          0,
        ),
      ),
    ],
    0,
  )
  try {
    let _ = session.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
    fail("expected ResponseIdMismatch for a multi-varbind GET reply")
  } catch {
    @session.SnmpError::ResponseIdMismatch => ()
    e => fail("expected ResponseIdMismatch, got \{Repr(e)}")
  }
}
