///|
/// The clock cases at the session layer: what a client sends, what a
/// receiver accepts, and what both do when time has passed.
///
/// Every case drives a fake clock (`clock_test.mbt`), because the bug
/// these protect against — a clock frozen at the value discovery saw —
/// only shows up after two and a half minutes of real running.

///|
test "a trap carries a clock that keeps moving" {
  let clock = FakeClock::new()
  let box = Outbox::new([])
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let client = @session.V3Client::new(box, "192.0.2.1", 162, security, 50, 0)
  client.set_clock(clock_of(clock))
  client.set_local_engine(sender_engine()) // boots 3, time 42
  client.trap(1, @mib.link_down(), [])
  clock.advance(10)
  client.trap(2, @mib.link_up(), [])
  let first = @snmpv3.V3Message::decode(box.out[0].2) catch {
    _ => fail("the first trap did not decode")
  }
  let second = @snmpv3.V3Message::decode(box.out[1].2) catch {
    _ => fail("the second trap did not decode")
  }
  // A sender that kept the clock it started with would be refused by
  // every receiver once the window passed; this is the fix, seen from
  // the wire.
  inspect(first.engine.time, content="42")
  inspect(second.engine.time, content="52")
  // It did not restart, so the boot count is unchanged.
  inspect(second.engine.boots, content="3")
}

///|
test "a replayed trap is refused once it is older than the window" {
  let clock = FakeClock::new()
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let wire = v3_trap_wire(sender_engine(), security, 1, 1, @mib.link_down(), [])
  let box = Outbox::new([v3_datagram(wire)])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  receiver.set_clock(clock_of(clock))
  // The first message from an engine is taken at its word: that is how
  // USM learns a sender it has never talked to.
  let first = receiver.recv(10)
  inspect(first.kind == TrapV2, content="true")
  // The same bytes again, 200 seconds later. It authenticates perfectly
  // — nothing about it changed — which is exactly why the clock has to
  // be what refuses it.
  clock.advance(200)
  box.inbox.push(v3_datagram(wire))
  let outcome = try {
    let _ = receiver.recv(10)
    "accepted"
  } catch {
    @session.SnmpError::NoResponse => "timeout"
    _ => "other"
  }
  inspect(outcome, content="timeout")
  inspect(receiver.rejected(), content="1")
}

///|
test "a sender whose clock moves stays inside the window" {
  let clock = FakeClock::new()
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let box = Outbox::new([])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  receiver.set_clock(clock_of(clock))
  // First message: bootstraps the sender at engine time 42.
  box.inbox.push(
    v3_datagram(
      v3_trap_wire(sender_engine(), security, 1, 1, @mib.link_down(), []),
    ),
  )
  let _ = receiver.recv(10)
  // 140 seconds later the sender's clock has moved with it, so the
  // message is still current even though a lot of wall time passed.
  clock.advance(140)
  let later : @snmpv3.Engine = { id: sender_engine().id, boots: 3, time: 182, }
  box.inbox.push(
    v3_datagram(v3_trap_wire(later, security, 2, 2, @mib.link_up(), [])),
  )
  let second = receiver.recv(10)
  inspect(second.kind == TrapV2, content="true")
  inspect(receiver.rejected(), content="0")
}

///|
test "an acknowledgement carries a clock that keeps moving" {
  let clock = FakeClock::new()
  let security = v3_test_security(b"monitor", b"authpass", b"privpass")
  let box = Outbox::new([])
  let receiver = @session.Receiver::v3(box, receiver_engine(), security)
  receiver.set_clock(clock_of(clock))
  box.inbox.push(
    v3_datagram(
      v3_inform_wire(
        receiver_engine(),
        security,
        1,
        4242,
        900,
        @mib.cold_start(),
        [],
      ),
    ),
  )
  let _ = receiver.recv(10)
  let first = @snmpv3.V3Message::decode(box.out[0].2) catch {
    _ => fail("the first acknowledgement did not decode")
  }
  // The receiver's engine starts at time 7.
  inspect(first.engine.time, content="7")
  clock.advance(20)
  // A sender that has been talking to us for a while keeps using the
  // clock it discovered; twenty seconds later it is still within the
  // window, and the reply has to move with our clock or the sender will
  // refuse it.
  box.inbox.push(
    v3_datagram(
      v3_inform_wire(
        receiver_engine(),
        security,
        2,
        4243,
        901,
        @mib.cold_start(),
        [],
      ),
    ),
  )
  let _ = receiver.recv(10)
  let second = @snmpv3.V3Message::decode(box.out[1].2) catch {
    _ => fail("the second acknowledgement did not decode")
  }
  inspect(second.engine.time, content="27")
}

///|
test "a reply whose clock is far behind is refused" {
  let clock = FakeClock::new()
  let signer : @snmpv3.Security = {
    level: @snmpv3.AuthNoPriv,
    user: b"monitor",
    auth_protocol: @snmpv3.Md5,
    auth_password: b"authpass",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
  let agent = FakeV3Agent::new(system_group())
  agent.security = Some(signer)
  let client = v3_auth_client_of(agent, signer)
  client.set_clock(clock_of(clock))
  // Discovery and one read: the agent's clock is 100 in this fake.
  let _ = client.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
  clock.advance(200)
  let stale = try {
    let _ = client.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
    false
  } catch {
    @session.SnmpError::Security(@snmpv3.V3Error::OutsideTimeWindow) => true
    _ => false
  }
  inspect(stale, content="true")
}

///|
test "a notInTimeWindow Report makes the client learn the clock again" {
  let clock = FakeClock::new()
  let agent = FakeV3Agent::new(system_group())
  agent.stale_once = true
  let client = v3_client_of(agent)
  client.set_clock(clock_of(clock))
  // The first attempt is refused with the counter that means "your clock
  // is out of step". That is not something the caller can fix, so the
  // client re-discovers once and retries instead of getting stuck.
  let vb = client.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
  match vb.value {
    @ber.BerValue::OctetString(b) => inspect(b, content="b\"Linux testbox\"")
    other => fail("expected an OctetString, got \{Repr(other)}")
  }
}
