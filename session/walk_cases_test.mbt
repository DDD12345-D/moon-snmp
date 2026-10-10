///|
/// The walk cases themselves. The fake agent and helpers live in
/// `walk_test.mbt`.

///|
test "walk of a group returns every leaf under it, in order" {
  let agent = FakeAgent::new(system_group())
  let session = session_of(agent)
  let entries = session.walk(oid("1, 3, 6, 1, 2, 1, 1"), 0)
  inspect(
    walk_shape(entries),
    content="1.3.6.1.2.1.1.1.0=string, 1.3.6.1.2.1.1.2.0=oid, 1.3.6.1.2.1.1.3.0=ticks, 1.3.6.1.2.1.1.4.0=string, 1.3.6.1.2.1.1.5.0=string, 1.3.6.1.2.1.1.6.0=string",
  )
  // 6 rows collected; the 7th GETNEXT would step out of the subtree
  // and stop the walk, so exactly 6 was enough — but the walk does one
  // extra GETNEXT to discover the boundary, which is correct.
  inspect(agent.next_calls, content="7")
}

///|
test "walk of a scalar instance returns just that one value" {
  // snmpwalk on a scalar OID (…sysDescr.0) prints that one value. The
  // walk reaches it with an initial GET rather than GETNEXT, because
  // GETNEXT from the instance would jump straight out of the subtree.
  let agent = FakeAgent::new(system_group())
  let session = session_of(agent)
  let entries = session.walk(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"), 0)
  inspect(entries.length(), content="1")
  inspect(entries[0].name.to_dotted(), content="1.3.6.1.2.1.1.1.0")
  match entries[0].value {
    @ber.BerValue::OctetString(b) => inspect(b, content="b\"Linux testbox\"")
    _ => fail("expected an OctetString")
  }
}

///|
test "walk stops at the first OID outside the subtree" {
  let agent = FakeAgent::new(system_group())
  let session = session_of(agent)
  // Walk a single column's instance space: nothing under it, so the
  // walk gets noSuchObject for the root and the first GETNEXT already
  // leaves the subtree.
  let entries = session.walk(oid("1, 3, 6, 1, 2, 1, 1, 7"), 0)
  inspect(entries.length(), content="0")
}

///|
test "walk stops at endOfMibView" {
  // Rows end at the boundary of what we walk, and there is nothing
  // after the last row we ask about.
  let agent = FakeAgent::new([
    row("1, 3, 6, 1, 2, 1, 1, 1, 0", @ber.BerValue::OctetString(b"a")),
    row("1, 3, 6, 1, 2, 1, 1, 2, 0", @ber.BerValue::OctetString(b"b")),
  ])
  let session = session_of(agent)
  let entries = session.walk(oid("1, 3, 6, 1, 2, 1, 1"), 0)
  inspect(
    walk_shape(entries),
    content="1.3.6.1.2.1.1.1.0=string, 1.3.6.1.2.1.1.2.0=string",
  )
}

///|
test "walk honours max_steps and stops early" {
  let agent = FakeAgent::new(system_group())
  let session = session_of(agent)
  let entries = session.walk(oid("1, 3, 6, 1, 2, 1, 1"), 3)
  inspect(entries.length(), content="3")
  // Stopping early means fewer GETNEXTs: 1 for the 3rd entry's
  // successor is not needed, so the count stays small.
  inspect(agent.next_calls <= 3, content="true")
}

///|
test "walk stops when the agent fails to advance" {
  // A broken agent that keeps answering with the same OID would loop
  // forever without the non-advancing guard. `StuckAgent` returns one
  // fixed row for every GETNEXT, whatever it was asked for.
  let session = @session.Session::new(
    StuckAgent::new(oid("1, 3, 6, 1, 2, 1, 1, 1, 0")),
    "127.0.0.1",
    16161,
    @pdu.V2c,
    b"public",
    50,
    0,
    1000,
  )
  let entries = session.walk(oid("1, 3, 6, 1, 2, 1, 1"), 0)
  // The first GETNEXT returns the row; the second returns the same row
  // and the guard stops the walk instead of looping.
  inspect(entries.length(), content="1")
}

///|
test "walk_bulk returns the same leaves as walk" {
  let agent = FakeAgent::new(system_group())
  let session = session_of(agent)
  let entries = session.walk_bulk(oid("1, 3, 6, 1, 2, 1, 1"), 4, 0)
  inspect(
    walk_shape(entries),
    content="1.3.6.1.2.1.1.1.0=string, 1.3.6.1.2.1.1.2.0=oid, 1.3.6.1.2.1.1.3.0=ticks, 1.3.6.1.2.1.1.4.0=string, 1.3.6.1.2.1.1.5.0=string, 1.3.6.1.2.1.1.6.0=string",
  )
}

///|
test "walk_bulk needs fewer round trips than walk" {
  let by_next = FakeAgent::new(system_group())
  let next_session = session_of(by_next)
  let _ = next_session.walk(oid("1, 3, 6, 1, 2, 1, 1"), 0)

  let by_bulk = FakeAgent::new(system_group())
  let bulk_session = session_of(by_bulk)
  let _ = bulk_session.walk_bulk(oid("1, 3, 6, 1, 2, 1, 1"), 10, 0)

  // GETNEXT costs one round trip per step plus the boundary probe;
  // GETBULK with max-repetitions=10 covers the whole group in one go.
  inspect(by_bulk.bulk_calls, content="1")
  inspect(by_next.next_calls > by_bulk.bulk_calls, content="true")
}

///|
test "walk_bulk discards the tail of a reply that left the subtree" {
  // max-repetitions=10 asks for 10 successors in one reply, so the
  // reply contains rows past the system group. Only the in-subtree ones
  // may be kept.
  let agent = FakeAgent::new(system_group())
  let session = session_of(agent)
  let entries = session.walk_bulk(oid("1, 3, 6, 1, 2, 1, 1"), 10, 0)
  inspect(entries.length(), content="6")
  inspect(entries[5].name.to_dotted(), content="1.3.6.1.2.1.1.6.0")
}

///|
test "walk_bulk honours max_steps across a multi-entry reply" {
  let agent = FakeAgent::new(system_group())
  let session = session_of(agent)
  let entries = session.walk_bulk(oid("1, 3, 6, 1, 2, 1, 1"), 10, 2)
  inspect(entries.length(), content="2")
}

///|
test "an empty subtree walks to nothing" {
  let agent = FakeAgent::new([])
  let session = session_of(agent)
  let entries = session.walk(oid("1, 3, 6, 1, 2, 1, 1"), 0)
  inspect(entries.length(), content="0")
}
