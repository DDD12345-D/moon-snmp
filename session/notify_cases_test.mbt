///|
/// The notification and receiver cases. The fakes live in
/// `notify_test.mbt`.

///|
test "a v2c trap is accepted with its origin and its varbinds" {
  let mailbox = Mailbox::new([
    datagram_of(
      trap_v2_wire(77, 123456, @mib.link_down(), [if_index_varbind(2)]),
      "192.0.2.7",
      54321,
    ),
  ])
  let receiver = receiver_over(mailbox, Some(b"public"))
  let n = receiver.recv(10)
  match n.kind {
    TrapV2 => ()
    other => fail("expected TrapV2, got \{Repr(other)}")
  }
  inspect(n.source_addr, content="192.0.2.7")
  inspect(n.source_port, content="54321")
  inspect(n.request_id(), content="77")
  // Three var-binds: the two mandatory ones plus what the sender added.
  inspect(n.varbinds().length(), content="3")
  inspect(Repr(n.uptime()), content="Some(123456)")
  match n.trap_oid() {
    Some(o) => inspect(o.to_dotted(), content="1.3.6.1.6.3.1.1.5.3")
    None => fail("expected a trap OID")
  }
  inspect(receiver.accepted(), content="1")
  inspect(receiver.rejected(), content="0")
}

///|
test "an inform is accepted and acknowledged with the same varbinds" {
  let mailbox = Mailbox::new([
    datagram_of(
      @pdu.Message::new(
        @pdu.V2c,
        b"public",
        @pdu.Pdu::request(@pdu.InformRequest, 4242, [
          @pdu.VarBind::new(@mib.sys_up_time(), @ber.BerValue::TimeTicks(900)),
          @pdu.VarBind::new(
            @mib.snmp_trap_oid(),
            @ber.BerValue::ObjectIdentifier(@mib.cold_start()),
          ),
          if_index_varbind(1),
        ]),
      ),
      "198.51.100.4",
      1161,
    ),
  ])
  let receiver = receiver_over(mailbox, Some(b"public"))
  let n = receiver.recv(10)
  match n.kind {
    Inform => ()
    other => fail("expected Inform, got \{Repr(other)}")
  }
  // The acknowledgement must go back to the datagram's origin, not to
  // any configured address, and must echo the request id and values.
  inspect(mailbox.sent.length(), content="1")
  inspect(mailbox.sent[0].host, content="198.51.100.4")
  inspect(mailbox.sent[0].port, content="1161")
  let ack = @pdu.Message::decode(mailbox.sent[0].data)
  inspect(ack.pdu.request_id(), content="4242")
  inspect(ack.community, content="b\"public\"")
  match ack.pdu {
    @pdu.Generic(p) => {
      match p.pdu_type {
        @pdu.Response => ()
        t => fail("expected a Response, got \{Repr(t)}")
      }
      inspect(p.error_status.to_int(), content="0")
      inspect(p.error_index, content="0")
      inspect(p.varbinds.length(), content="3")
    }
    _ => fail("expected a generic PDU")
  }
}

///|
test "a v2c trap is never acknowledged" {
  // Only an inform asks for a reply; answering a trap would be noise
  // the sender never asked for.
  let mailbox = Mailbox::new([
    datagram_of(trap_v2_wire(1, 10, @mib.link_up(), []), "192.0.2.7", 54321),
  ])
  let receiver = receiver_over(mailbox, None)
  let _ = receiver.recv(10)
  inspect(mailbox.sent.length(), content="0")
}

///|
test "a v1 trap is accepted and its generic code translated to an OID" {
  // A v1 trap names itself with a small integer, so a receiver has to
  // do the translation to be able to treat it like a v2c one.
  let v1 = @pdu.Message::new(
    @pdu.V1,
    b"public",
    @pdu.Pdu::TrapV1({
      enterprise: @oid.Oid::parse("1.3.6.1.4.1.8072"),
      agent_addr: b"\xc0\x00\x02\x07",
      generic_trap: 2,
      specific_trap: 0,
      time_stamp: 555,
      varbinds: [if_index_varbind(3)],
    }),
  )
  let mailbox = Mailbox::new([datagram_of(v1, "192.0.2.7", 54321)])
  let receiver = receiver_over(mailbox, Some(b"public"))
  let n = receiver.recv(10)
  match n.kind {
    TrapV1 => ()
    other => fail("expected TrapV1, got \{Repr(other)}")
  }
  // generic 2 is linkDown.
  match n.trap_oid() {
    Some(o) => inspect(o.to_dotted(), content="1.3.6.1.6.3.1.1.5.3")
    None => fail("expected a trap OID")
  }
  // The v1 body is available as-is for the fields that have no v2c
  // equivalent.
  match n.trap_v1() {
    Some(t) => {
      inspect(t.generic_trap, content="2")
      inspect(t.enterprise.to_dotted(), content="1.3.6.1.4.1.8072")
      inspect(t.time_stamp, content="555")
    }
    None => fail("expected a v1 trap body")
  }
  // A v1 trap has no request id field at all.
  inspect(n.request_id(), content="0")
  // Its uptime lives in the trap body rather than a var-bind, and the
  // uniform accessor finds it there: the same number in the same unit.
  inspect(Repr(n.uptime()), content="Some(555)")
}

///|
test "an enterprise-specific v1 trap translates to enterprise.0.specific" {
  let v1 = @pdu.Message::new(
    @pdu.V1,
    b"public",
    @pdu.Pdu::TrapV1({
      enterprise: @oid.Oid::parse("1.3.6.1.4.1.9"),
      agent_addr: b"\xc0\x00\x02\x07",
      generic_trap: 6,
      specific_trap: 7,
      time_stamp: 1,
      varbinds: [],
    }),
  )
  let mailbox = Mailbox::new([datagram_of(v1, "192.0.2.7", 54321)])
  let receiver = receiver_over(mailbox, None)
  let n = receiver.recv(10)
  // RFC 2576 §3.1: the enterprise-specific form becomes
  // enterprise.0.specific so a single OID names every v1 trap.
  match n.trap_oid() {
    Some(o) => inspect(o.to_dotted(), content="1.3.6.1.4.1.9.0.7")
    None => fail("expected a trap OID")
  }
}

///|
test "a wrong community is discarded, not answered" {
  // RFC 1157 §4.1: a bad community gets dropped without a reply. A
  // receiver that answered would be a probe's best friend.
  let mailbox = Mailbox::new([
    datagram_of(
      trap_v2_wire_from(b"private", 1, 10, @mib.link_up(), []),
      "192.0.2.7",
      54321,
    ),
  ])
  let receiver = receiver_over(mailbox, Some(b"public"))
  try {
    let _ = receiver.recv(10)
    fail("expected NoResponse for a rejected community")
  } catch {
    @session.SnmpError::NoResponse => ()
    e => fail("expected NoResponse, got \{Repr(e)}")
  }
  inspect(receiver.accepted(), content="0")
  inspect(receiver.rejected(), content="1")
  inspect(mailbox.sent.length(), content="0")
}

///|
test "with no configured community anything is accepted" {
  let mailbox = Mailbox::new([
    datagram_of(trap_v2_wire(1, 10, @mib.link_up(), []), "192.0.2.7", 54321),
  ])
  let receiver = receiver_over(mailbox, None)
  let _ = receiver.recv(10)
  inspect(receiver.accepted(), content="1")
}

///|
test "a malformed datagram is discarded without stopping the receiver" {
  let mailbox = Mailbox::new([
    { from_addr: "203.0.113.9", from_port: 9999, data: b"\x30\x82\xff", },
    datagram_of(trap_v2_wire(5, 10, @mib.link_up(), []), "192.0.2.7", 54321),
  ])
  let receiver = receiver_over(mailbox, None)
  // The junk is skipped and the real trap that follows is returned.
  let n = receiver.recv(10)
  inspect(n.request_id(), content="5")
  inspect(receiver.rejected(), content="1")
  inspect(receiver.accepted(), content="1")
}

///|
test "a Response arriving at a receiver is not a notification" {
  // A stray answer to somebody else's request must not be mistaken for
  // a trap; only the three notification shapes count.
  let mailbox = Mailbox::new([
    datagram_of(
      @pdu.Message::new(
        @pdu.V2c,
        b"public",
        @pdu.Pdu::response(1, @pdu.NoError, 0, []),
      ),
      "203.0.113.9",
      9999,
    ),
  ])
  let receiver = receiver_over(mailbox, None)
  try {
    let _ = receiver.recv(10)
    fail("expected NoResponse")
  } catch {
    @session.SnmpError::NoResponse => ()
    e => fail("expected NoResponse, got \{Repr(e)}")
  }
  inspect(receiver.rejected(), content="1")
  inspect(receiver.accepted(), content="0")
}

///|
test "an inform that cannot be addressed is counted, not lost" {
  // Without a sender address there is nowhere to send the
  // acknowledgement. The notification is still delivered, and the
  // failure is visible in the counter so it is not silent.
  let mailbox = Mailbox::new([
    {
      from_addr: "",
      from_port: 0,
      data: @pdu.Message::new(
        @pdu.V2c,
        b"public",
        @pdu.Pdu::request(@pdu.InformRequest, 9, [
          @pdu.VarBind::new(@mib.sys_up_time(), @ber.BerValue::TimeTicks(1)),
          @pdu.VarBind::new(
            @mib.snmp_trap_oid(),
            @ber.BerValue::ObjectIdentifier(@mib.cold_start()),
          ),
        ]),
      ).encode(),
    },
  ])
  let receiver = receiver_over(mailbox, None)
  let n = receiver.recv(10)
  match n.kind {
    Inform => ()
    other => fail("expected Inform, got \{Repr(other)}")
  }
  inspect(receiver.accepted(), content="1")
  inspect(receiver.unacknowledged(), content="1")
  inspect(mailbox.sent.length(), content="0")
}

///|
test "a session's inform is an InformRequest with the mandatory head" {
  // The sender half, checked from the wire bytes it produced: an inform
  // must carry sysUpTime.0 then snmpTrapOID.0 before anything the
  // caller added (RFC 3416 §4.2.6).
  let mailbox = Mailbox::empty()
  let session = session_over(mailbox)
  // No reply will ever come, so this raises; the bytes were still sent.
  try {
    let _ = session.inform(4242, @mib.link_down(), [if_index_varbind(2)])
    fail("expected NoResponse with no receiver listening")
  } catch {
    @session.SnmpError::NoResponse => ()
    e => fail("expected NoResponse, got \{Repr(e)}")
  }
  inspect(mailbox.sent.length(), content="1")
  inspect(mailbox.sent[0].host, content="10.0.0.9")
  inspect(mailbox.sent[0].port, content="162")
  let message = @pdu.Message::decode(mailbox.sent[0].data)
  match message.pdu {
    @pdu.Generic(p) => {
      match p.pdu_type {
        @pdu.InformRequest => ()
        t => fail("expected InformRequest, got \{Repr(t)}")
      }
      // The request id is the one the session allocated, not the
      // placeholder zero the caller passed.
      inspect(p.request_id, content="700")
      inspect(p.varbinds.length(), content="3")
      inspect(p.varbinds[0].name.to_dotted(), content="1.3.6.1.2.1.1.3.0")
      inspect(p.varbinds[1].name.to_dotted(), content="1.3.6.1.6.3.1.1.4.1.0")
      match p.varbinds[1].value {
        @ber.BerValue::ObjectIdentifier(o) =>
          inspect(o.to_dotted(), content="1.3.6.1.6.3.1.1.5.3")
        _ => fail("expected an OBJECT IDENTIFIER for snmpTrapOID.0")
      }
      match p.varbinds[0].value {
        @ber.BerValue::TimeTicks(n) => inspect(n, content="4242")
        _ => fail("expected TimeTicks for sysUpTime.0")
      }
    }
    _ => fail("expected a generic PDU")
  }
}

///|
test "what a session sends as a trap is what a receiver accepts" {
  // The two halves against each other: encode with the sender, decode
  // with the receiver. A drift in either would show up here.
  let outbox = Mailbox::empty()
  let session = session_over(outbox)
  session.trap_v2(31337, @mib.authentication_failure(), [
    @pdu.VarBind::new(
      @mib.if_descr(),
      @ber.BerValue::OctetString(@utf8.encode("eth0")),
    ),
  ])
  inspect(outbox.sent.length(), content="1")

  let inbox = Mailbox::new([
    { from_addr: "10.0.0.9", from_port: 40000, data: outbox.sent[0].data, },
  ])
  let receiver = receiver_over(inbox, Some(b"public"))
  let n = receiver.recv(10)
  match n.kind {
    TrapV2 => ()
    other => fail("expected TrapV2, got \{Repr(other)}")
  }
  match n.trap_oid() {
    Some(o) => inspect(o.to_dotted(), content="1.3.6.1.6.3.1.1.5.5")
    None => fail("expected a trap OID")
  }
  inspect(Repr(n.uptime()), content="Some(31337)")
  inspect(n.varbinds().length(), content="3")
  // The request id the sender allocated arrives with the trap.
  inspect(n.request_id(), content="700")
  match n.varbinds()[2].value {
    @ber.BerValue::OctetString(b) => inspect(b, content="b\"eth0\"")
    _ => fail("expected an OctetString")
  }
}

///|
test "what a session sends as a v1 trap is what a receiver accepts" {
  let outbox = Mailbox::empty()
  let session = session_over(outbox)
  session.trap_v1(
    @oid.Oid::parse("1.3.6.1.4.1.8072"),
    b"\x0a\x00\x00\x09",
    3,
    0,
    8080,
    [if_index_varbind(4)],
  )
  let inbox = Mailbox::new([
    { from_addr: "10.0.0.9", from_port: 40000, data: outbox.sent[0].data, },
  ])
  let receiver = receiver_over(inbox, Some(b"public"))
  let n = receiver.recv(10)
  match n.kind {
    TrapV1 => ()
    other => fail("expected TrapV1, got \{Repr(other)}")
  }
  match n.trap_v1() {
    Some(t) => {
      inspect(t.generic_trap, content="3")
      inspect(t.time_stamp, content="8080")
      inspect(@mib.format_ip_address(t.agent_addr), content="10.0.0.9")
    }
    None => fail("expected a v1 trap body")
  }
  // generic 3 is linkUp.
  match n.trap_oid() {
    Some(o) => inspect(o.to_dotted(), content="1.3.6.1.6.3.1.1.5.4")
    None => fail("expected a trap OID")
  }
}

///|
test "consecutive traps draw different request ids" {
  let outbox = Mailbox::empty()
  let session = session_over(outbox)
  session.trap_v2(1, @mib.cold_start(), [])
  session.trap_v2(2, @mib.warm_start(), [])
  let first = @pdu.Message::decode(outbox.sent[0].data)
  let second = @pdu.Message::decode(outbox.sent[1].data)
  inspect(first.pdu.request_id(), content="700")
  inspect(second.pdu.request_id(), content="701")
}

///|
test "a v1 trap travels in a v1 message, whatever the session says" {
  // A v1 trap body inside a v2c message is not a valid combination: a
  // lenient receiver logs it under the wrong version and a strict one
  // drops it. The notification kind has to decide the version, not the
  // session. The session here is deliberately v2c.
  let outbox = Mailbox::empty()
  let session = session_over(outbox)
  session.trap_v1(
    @oid.Oid::parse("1.3.6.1.4.1.8072"),
    b"\x7f\x00\x00\x01",
    6,
    7,
    99,
    [],
  )
  let message = @pdu.Message::decode(outbox.sent[0].data)
  match message.version {
    @pdu.V1 => ()
    v => fail("expected a v1 message, got version \{v.to_int()}")
  }
  match message.pdu {
    @pdu.TrapV1(_) => ()
    _ => fail("expected a v1 trap body")
  }
}

///|
test "a v2c trap travels in a v2c message, whatever the session says" {
  // The mirror case: a v1 session must still send v2c traps as v2c,
  // because a TrapV2 PDU does not exist in v1.
  let outbox = Mailbox::empty()
  let v1_session = @session.Session::new(
    outbox,
    "10.0.0.9",
    162,
    @pdu.V1,
    b"public",
    10,
    0,
    700,
  )
  v1_session.trap_v2(5, @mib.cold_start(), [])
  let message = @pdu.Message::decode(outbox.sent[0].data)
  match message.version {
    @pdu.V2c => ()
    v => fail("expected a v2c message, got version \{v.to_int()}")
  }
}

///|
test "an inform travels in a v2c message even from a v1 session" {
  // An inform does not exist in v1 at all.
  let outbox = Mailbox::empty()
  let v1_session = @session.Session::new(
    outbox,
    "10.0.0.9",
    162,
    @pdu.V1,
    b"public",
    10,
    0,
    700,
  )
  try {
    let _ = v1_session.inform(5, @mib.cold_start(), [])
    fail("expected NoResponse with no receiver listening")
  } catch {
    @session.SnmpError::NoResponse => ()
    e => fail("expected NoResponse, got \{Repr(e)}")
  }
  let message = @pdu.Message::decode(outbox.sent[0].data)
  match message.version {
    @pdu.V2c => ()
    v => fail("expected a v2c message, got version \{v.to_int()}")
  }
}

///|
test "a v1 get can be sent from a v2c session" {
  // The version override is useful outside notifications too: an old
  // device that only speaks v1 can be queried without a second session.
  let outbox = Mailbox::empty()
  let session = session_over(outbox)
  try {
    let _ = session.request_versioned(
      @pdu.V1,
      @pdu.Pdu::request(@pdu.GetRequest, 0, [
        @pdu.VarBind::new(@mib.sys_descr(), @ber.BerValue::Null),
      ]),
    )
    fail("expected NoResponse with no agent listening")
  } catch {
    @session.SnmpError::NoResponse => ()
    e => fail("expected NoResponse, got \{Repr(e)}")
  }
  let message = @pdu.Message::decode(outbox.sent[0].data)
  match message.version {
    @pdu.V1 => ()
    v => fail("expected a v1 message, got version \{v.to_int()}")
  }
}
