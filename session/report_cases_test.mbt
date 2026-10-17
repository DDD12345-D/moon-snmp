///|
/// What a receiver says when it refuses a v3 message.
///
/// RFC 3414 has an authoritative engine answer with a Report naming the
/// `usmStats` counter it incremented, rather than dropping the datagram.
/// That difference is the whole point: without it a sender waits for a
/// timeout and cannot tell a wrong password from a wrong clock from a
/// device that is simply off.

///|
/// The Report a receiver sent back, decoded far enough to read.
fn report_of(box : Outbox) -> (@snmpv3.V3Message, @pdu.Pdu) raise {
  if box.out.length() != 1 {
    fail("expected exactly one report, got \{box.out.length()}")
  }
  let message = @snmpv3.V3Message::decode(box.out[0].2) catch {
    _ => fail("the report did not decode as a v3 message")
  }
  let pdu = match message.scoped() {
    Some(scoped) => scoped.pdu
    None => fail("the report was encrypted")
  }
  (message, pdu)
}

///|
/// Whether a Report carries this counter, and how often it has been
/// counted.
fn carries(pdu : @pdu.Pdu, kind : @snmpv3.ReportKind, count : Int) -> Bool {
  match pdu {
    @pdu.Generic(p) =>
      if p.pdu_type != @pdu.Report || p.varbinds.length() != 1 {
        false
      } else {
        let vb = p.varbinds[0]
        vb.name.compare(@snmpv3.ReportKind::oid(kind)) == 0 &&
        Repr(vb.value).to_string() == "Counter32(\{count})"
      }
    _ => false
  }
}

///|
test "an unknown user is told so instead of being left to time out" {
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let stranger = v3_test_security(b"stranger", b"authpass", b"privpass")
  let wire = v3_inform_wire(
    receiver_engine(),
    stranger,
    1,
    4242,
    900,
    @mib.cold_start(),
    [],
  )
  let box = Outbox::new([v3_datagram(wire)])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  let outcome = try {
    let _ = receiver.recv(10)
    "notification"
  } catch {
    @session.SnmpError::NoResponse => "timeout"
    _ => "other"
  }
  inspect(outcome, content="timeout")
  inspect(receiver.rejected(), content="1")
  let (message, pdu) = report_of(box)
  // Nothing about the sender is trusted yet, so the Report cannot be
  // authenticated.
  inspect(message.flags.authenticated, content="false")
  inspect(message.engine.id == receiver_engine().id, content="true")
  inspect(carries(pdu, @snmpv3.UnknownUserNames, 1), content="true")
}

///|
test "a security level below the user's minimum is named as such" {
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  // The same user and password, but authenticated and not encrypted.
  let weaker : @snmpv3.Security = {
    level: @snmpv3.AuthNoPriv,
    user: b"monitor",
    auth_protocol: @snmpv3.Md5,
    auth_password: b"authpass",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
  let wire = v3_inform_wire(
    receiver_engine(),
    weaker,
    2,
    4243,
    901,
    @mib.cold_start(),
    [],
  )
  let box = Outbox::new([v3_datagram(wire)])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  // The refusal is a Report, not a notification, so the wait times out.
  let outcome = try {
    let _ = receiver.recv(10)
    "notification"
  } catch {
    @session.SnmpError::NoResponse => "timeout"
    _ => "other"
  }
  inspect(outcome, content="timeout")
  let (_, pdu) = report_of(box)
  // The counter is what tells a sender "the password was fine, the level
  // was not" — a wrong-digest Report would send it changing the password.
  inspect(carries(pdu, @snmpv3.UnsupportedSecLevels, 1), content="true")
}

///|
test "a wrong password is answered with the digest counter" {
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let wrong = v3_test_security(b"monitor", b"typo", b"privpass")
  let wire = v3_inform_wire(
    receiver_engine(),
    wrong,
    3,
    4244,
    902,
    @mib.cold_start(),
    [],
  )
  let box = Outbox::new([v3_datagram(wire)])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  // The refusal is a Report, not a notification, so the wait times out.
  let outcome = try {
    let _ = receiver.recv(10)
    "notification"
  } catch {
    @session.SnmpError::NoResponse => "timeout"
    _ => "other"
  }
  inspect(outcome, content="timeout")
  let (message, pdu) = report_of(box)
  inspect(message.flags.authenticated, content="false")
  inspect(carries(pdu, @snmpv3.WrongDigests, 1), content="true")
}

///|
test "a clock outside the window gets a signed report saying so" {
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  // Our engine says time 7; the sender claims 500, which is 493 seconds
  // away — a replayed message, or a sender that never updated its clock.
  let ahead : @snmpv3.Engine = {
    id: receiver_engine().id,
    boots: 1,
    time: 500,
  }
  let wire = v3_inform_wire(ahead, security, 4, 4245, 903, @mib.cold_start(), [])
  let box = Outbox::new([v3_datagram(wire)])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  // The refusal is a Report, not a notification, so the wait times out.
  let outcome = try {
    let _ = receiver.recv(10)
    "notification"
  } catch {
    @session.SnmpError::NoResponse => "timeout"
    _ => "other"
  }
  inspect(outcome, content="timeout")
  let message = @snmpv3.V3Message::decode(box.out[0].2) catch {
    _ => fail("the report did not decode")
  }
  // The message was authentic, so this one is signed — and encrypted at
  // the same level: the sender proved who it is and can read the answer.
  inspect(message.flags.authenticated, content="true")
  inspect(message.flags.encrypted, content="true")
  let keys = security.localize(receiver_engine().id) catch {
    _ => fail("the report key did not localize")
  }
  let opened = @snmpv3.open(box.out[0].2, security, keys) catch {
    _ => fail("the report did not verify")
  }
  let pdu = match opened.scoped() {
    Some(scoped) => scoped.pdu
    None => fail("the report did not open")
  }
  inspect(carries(pdu, @snmpv3.NotInTimeWindows, 1), content="true")
}

///|
test "a stale trap is dropped in silence" {
  // For a trap the sender is the authoritative engine, so this receiver
  // has nothing to report to it — and it would not believe us anyway.
  let clock = FakeClock::new()
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let wire = v3_trap_wire(sender_engine(), security, 5, 1, @mib.link_down(), [])
  let box = Outbox::new([v3_datagram(wire)])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  receiver.set_clock(clock_of(clock))
  let _ = receiver.recv(10)
  clock.advance(200)
  box.inbox.push(v3_datagram(wire))
  // The refusal is a Report, not a notification, so the wait times out.
  let outcome = try {
    let _ = receiver.recv(10)
    "notification"
  } catch {
    @session.SnmpError::NoResponse => "timeout"
    _ => "other"
  }
  inspect(outcome, content="timeout")
  inspect(receiver.rejected(), content="1")
  // The first message went nowhere (a trap is never acknowledged), and
  // the stale one certainly did not produce a Report.
  inspect(box.out.length(), content="0")
}
