///|
/// The clock rules themselves: no state, no sockets, just the two
/// comparisons RFC 3414 §3.2 makes.

///|
/// An engine for the tests.
fn engine_at(boots : Int, time : Int) -> @snmpv3.Engine {
  { id: b"\x80\x00\x1f\x88\x04clock", boots, time, }
}

///|
test "a clock inside the window is fresh" {
  inspect(
    Repr(@snmpv3.peer_timeliness(engine_at(1, 1000), engine_at(1, 1100))),
    content="Fresh",
  )
  // Exactly on the edge is still inside: the rule is "more than 150".
  inspect(
    Repr(@snmpv3.peer_timeliness(engine_at(1, 850), engine_at(1, 1000))),
    content="Fresh",
  )
}

///|
test "a clock more than a window behind is stale" {
  inspect(
    Repr(@snmpv3.peer_timeliness(engine_at(1, 800), engine_at(1, 1000))),
    content="Stale",
  )
}

///|
test "a clock ahead of ours is taken at its word" {
  // net-snmp does not refuse a message from the future: it records the
  // new clock instead. Refusing it would break a peer whose clock
  // legitimately jumped, and the window still bounds how far it can go
  // before this message is itself replayed past.
  inspect(
    Repr(@snmpv3.peer_timeliness(engine_at(1, 5000), engine_at(1, 1000))),
    content="Fresh",
  )
}

///|
test "a peer that restarted is recognised by its boots" {
  inspect(
    Repr(@snmpv3.peer_timeliness(engine_at(2, 3), engine_at(1, 1000))),
    content="Restarted",
  )
  inspect(
    Repr(@snmpv3.peer_timeliness(engine_at(1, 1000), engine_at(2, 1000))),
    content="Stale",
  )
}

///|
test "a message addressed to our own engine has to agree with us" {
  // Here we are the clock, so a message dated in the future is as wrong
  // as one dated in the past.
  inspect(
    Repr(@snmpv3.local_timeliness(engine_at(1, 1000), engine_at(1, 1100))),
    content="Fresh",
  )
  inspect(
    Repr(@snmpv3.local_timeliness(engine_at(1, 1000), engine_at(1, 1200))),
    content="Stale",
  )
  inspect(
    Repr(@snmpv3.local_timeliness(engine_at(2, 1000), engine_at(1, 1000))),
    content="Stale",
  )
}

///|
test "an advanced clock drops the fraction of a second" {
  let engine = engine_at(1, 100)
  inspect(engine.advanced(2500L).time, content="102")
  // Time does not run backwards, even if the machine's clock does.
  inspect(engine.advanced(-5000L).time, content="100")
}
