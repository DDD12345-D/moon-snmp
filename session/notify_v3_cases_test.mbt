///|
/// The v3 notification cases. The fakes and wire builders live in
/// `notify_v3_test.mbt`.
///
/// Two directions, and they are not symmetric: a trap is authoritative
/// for the sender's engine, an inform for the receiver's. Each test
/// pins that down by opening the message the way the other side would.

///|
test "a v3 trap is scoped to the sender's engine and carries the mandatory var-binds" {
  let box = Outbox::new([])
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let client = @session.V3Client::new(box, "192.0.2.1", 162, security, 50, 0)
  client.set_local_engine(sender_engine())
  client.trap(1234, @mib.link_down(), [if_index_varbind(2)])
  inspect(box.out.length(), content="1")
  let wire = box.out[0].2
  let message = @snmpv3.V3Message::decode(wire) catch {
    _ => fail("the trap did not decode as a v3 message")
  }
  // The header describes *us*, not the agent we might also be polling.
  inspect(message.engine.id == sender_engine().id, content="true")
  inspect(message.user, content="b\"monitor\"")
  // A trap is unconfirmed: nothing will answer it, so nothing may ask.
  inspect(message.flags.reportable, content="false")
  inspect(message.flags.authenticated, content="true")
  inspect(message.flags.encrypted, content="true")
  // The real check: a receiver that knows only the password, plus the
  // engine id it just read from the header, has to be able to open it.
  let keys = security.localize(message.engine.id) catch {
    _ => fail("the receiver could not localize the sender's key")
  }
  let opened = @snmpv3.open(wire, security, keys) catch {
    _ => fail("the receiver could not open the trap")
  }
  match opened.data {
    @snmpv3.Plain(scoped) => {
      let varbinds = scoped.pdu.varbinds()
      inspect(varbinds.length(), content="3")
      inspect(
        varbinds[0].name.to_dotted(),
        content=@mib.sys_up_time().to_dotted(),
      )
      match varbinds[1].value {
        @ber.BerValue::ObjectIdentifier(o) =>
          inspect(o.to_dotted(), content=@mib.link_down().to_dotted())
        other => fail("expected the trap OID, got \{Repr(other)}")
      }
    }
    @snmpv3.Encrypted(_) => fail("expected a readable scoped PDU")
  }
}

///|
test "a v3 trap without a local engine is refused instead of sent unsigned" {
  let box = Outbox::new([])
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let client = @session.V3Client::new(box, "192.0.2.1", 162, security, 50, 0)
  let refused = try {
    client.trap(1, @mib.link_down(), [])
    false
  } catch {
    @session.SnmpError::Security(_) => true
    _ => false
  }
  inspect(refused, content="true")
  inspect(box.out.length(), content="0")
}

///|
test "a v3 inform is addressed to the receiver's engine and waits for the ack" {
  // `FakeV3Agent` plays the receiver: it answers discovery with its own
  // engine id and acknowledges an inform with a Response. That the
  // client can complete the exchange is the point — an inform that does
  // not come back is the failure the PDU exists to prevent.
  let agent = FakeV3Agent::new(system_group())
  let client = v3_client_of(agent)
  let acked = client.inform(77, @mib.link_down(), [])
  // The two mandatory var-binds come back in the acknowledgement.
  inspect(acked.length(), content="2")
  inspect(agent.informs, content="1")
}

///|
test "a v3 trap from another engine is accepted, with who sent it" {
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let wire = v3_trap_wire(sender_engine(), security, 4242, @mib.link_down(), [
    if_index_varbind(2),
  ])
  let box = Outbox::new([v3_datagram(wire)])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  let n = receiver.recv(10)
  inspect(n.kind == TrapV2, content="true")
  inspect(n.version == @pdu.V3, content="true")
  inspect(n.source_addr, content="192.0.2.9")
  match n.v3 {
    Some(info) => {
      // A trap's authoritative engine is the sender's, not ours.
      inspect(info.engine_id == sender_engine().id, content="true")
      inspect(info.user, content="b\"monitor\"")
      inspect(info.level == @snmpv3.AuthPriv, content="true")
    }
    None => fail("expected the v3 context to be recorded")
  }
  match n.trap_oid() {
    Some(o) => inspect(o.to_dotted(), content=@mib.link_down().to_dotted())
    None => fail("expected a trap OID")
  }
  inspect(receiver.accepted(), content="1")
  inspect(receiver.rejected(), content="0")
  // A trap is never acknowledged.
  inspect(box.out.length(), content="0")
}

///|
test "a v3 trap signed with the wrong password is rejected" {
  let sender = v3_test_security(b"monitor", b"authpass", b"privpass")
  let receiver_security = v3_test_security(b"monitor", b"typo", b"privpass")
  let wire = v3_trap_wire(sender_engine(), sender, 1, @mib.link_down(), [])
  let box = Outbox::new([v3_datagram(wire)])
  let receiver = @session.Receiver::v3(
    box,
    receiver_engine(),
    receiver_security,
  )
  let outcome = try {
    let _ = receiver.recv(10)
    "accepted"
  } catch {
    @session.SnmpError::NoResponse => "timeout"
    _ => "other"
  }
  // The datagram is discarded, and the receiver keeps waiting: a wrong
  // password must not look like a notification, and must not stop it.
  inspect(outcome, content="timeout")
  inspect(receiver.rejected(), content="1")
  inspect(receiver.accepted(), content="0")
}

///|
test "a discovery probe is answered with a Report naming our engine" {
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let box = Outbox::new([v3_datagram(v3_discovery_wire(11))])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  let outcome = try {
    let _ = receiver.recv(10)
    "notification"
  } catch {
    @session.SnmpError::NoResponse => "timeout"
    _ => "other"
  }
  // A probe is not a notification, so the wait continues; what matters
  // is the Report that went back.
  inspect(outcome, content="timeout")
  inspect(receiver.discoveries(), content="1")
  inspect(box.out.length(), content="1")
  let report = @snmpv3.V3Message::decode(box.out[0].2) catch {
    _ => fail("the report did not decode")
  }
  inspect(report.engine.id == receiver_engine().id, content="true")
  inspect(report.flags.authenticated, content="false")
  match report.data {
    @snmpv3.Plain(scoped) =>
      match scoped.pdu {
        @pdu.Generic(p) => {
          inspect(p.pdu_type == @pdu.Report, content="true")
          inspect(p.request_id, content="11")
          match p.varbinds.get(0) {
            Some(vb) => {
              inspect(
                vb.name.to_dotted(),
                content=@snmpv3.usm_stats_unknown_engine_ids().to_dotted(),
              )
              inspect(Repr(vb.value), content="Counter32(1)")
            }
            None => fail("expected the usmStats counter")
          }
        }
        _ => fail("expected a Report PDU")
      }
    @snmpv3.Encrypted(_) => fail("a Report is not encrypted")
  }
}

///|
test "an inform addressed to us is acknowledged with a signed Response" {
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let wire = v3_inform_wire(
    receiver_engine(),
    security,
    4242,
    900,
    @mib.cold_start(),
    [],
  )
  let box = Outbox::new([v3_datagram(wire)])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  let n = receiver.recv(10)
  inspect(n.kind == Inform, content="true")
  inspect(receiver.accepted(), content="1")
  inspect(receiver.unacknowledged(), content="0")
  inspect(box.out.length(), content="1")
  // The sender derived its key from our engine id, so it can only verify
  // a reply signed with a key localized to the same id.
  let ack = box.out[0].2
  let message = @snmpv3.V3Message::decode(ack) catch {
    _ => fail("the acknowledgement did not decode")
  }
  inspect(message.engine.id == receiver_engine().id, content="true")
  let keys = security.localize(receiver_engine().id) catch {
    _ => fail("the acknowledgement key did not localize")
  }
  let opened = @snmpv3.open(ack, security, keys) catch {
    _ => fail("the acknowledgement did not verify")
  }
  match opened.data {
    @snmpv3.Plain(scoped) =>
      match scoped.pdu {
        @pdu.Generic(p) => {
          inspect(p.pdu_type == @pdu.Response, content="true")
          inspect(p.request_id, content="4242")
          // The acknowledgement echoes the inform's var-binds.
          inspect(p.varbinds.length(), content="2")
        }
        _ => fail("expected a Response PDU")
      }
    @snmpv3.Encrypted(_) => fail("expected a readable scoped PDU")
  }
}

///|
test "an inform addressed to another engine is accepted but not acknowledged" {
  // Only the authoritative engine may answer, and this message names a
  // different one. Verifying it is still possible (the key follows the
  // engine id in the header); answering it would be wrong.
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let wire = v3_inform_wire(
    sender_engine(),
    security,
    4242,
    900,
    @mib.cold_start(),
    [],
  )
  let box = Outbox::new([v3_datagram(wire)])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  let n = receiver.recv(10)
  inspect(n.kind == Inform, content="true")
  inspect(receiver.unacknowledged(), content="1")
  inspect(box.out.length(), content="0")
}
