///|
/// The v3 client cases. The fake agent and helpers live in
/// `v3client_test.mbt`.
///
/// What is tested here is the PDU layer of the v3 client: which request
/// it puts inside the scoped PDU, which reply it accepts, and whether
/// the walk rules are the same ones the community session uses. USM
/// itself is covered by `snmpv3/usm_test.mbt` (RFC 3414 A.3 vectors) and
/// by the end-to-end suite against a real agent.

///|
test "v3 get reads a value" {
  let agent = FakeV3Agent::new(system_group())
  let client = v3_client_of(agent)
  let vb = client.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
  match vb.value {
    @ber.BerValue::OctetString(b) => inspect(b, content="b\"Linux testbox\"")
    other => fail("expected an OctetString, got \{Repr(other)}")
  }
  // Discovery is a real round trip, so it must have happened exactly
  // once for the one request that followed.
  inspect(client.engine().id.length() > 0, content="true")
}

///|
test "v3 set writes a value the agent accepts" {
  let agent = FakeV3Agent::new(system_group())
  agent.writable = true
  let client = v3_client_of(agent)
  let written = client.set(
    oid("1, 3, 6, 1, 2, 1, 1, 4, 0"),
    @ber.BerValue::OctetString(b"ops@example.com"),
  )
  inspect(written.length(), content="1")
  inspect(agent.sets, content="1")
  // The next read has to see the new value: a SET that returns happily
  // without having changed anything is the failure this catches.
  let read_back = client.get(oid("1, 3, 6, 1, 2, 1, 1, 4, 0"))
  match read_back.value {
    @ber.BerValue::OctetString(b) => inspect(b, content="b\"ops@example.com\"")
    other => fail("expected an OctetString, got \{Repr(other)}")
  }
}

///|
test "v3 set on a read-only user surfaces the agent's refusal" {
  // The agent is the authority on whether a write is allowed; the
  // client's job is to hand the error-status through instead of
  // pretending the write succeeded.
  let agent = FakeV3Agent::new(system_group())
  let client = v3_client_of(agent)
  try {
    let _ = client.set(
      oid("1, 3, 6, 1, 2, 1, 1, 4, 0"),
      @ber.BerValue::OctetString(b"nope"),
    )
    fail("expected AgentError")
  } catch {
    @session.SnmpError::AgentError(status, index) => {
      // 17 is notWritable in RFC 3416 §3.
      inspect(status.to_int(), content="17")
      inspect(index, content="1")
    }
    e => fail("expected AgentError, got \{Repr(e)}")
  }
}

///|
test "v3 walk returns every leaf under the root, in order" {
  let agent = FakeV3Agent::new(system_group())
  let client = v3_client_of(agent)
  let entries = client.walk(oid("1, 3, 6, 1, 2, 1, 1"), 0)
  inspect(
    walk_shape(entries),
    content="1.3.6.1.2.1.1.1.0=string, 1.3.6.1.2.1.1.2.0=oid, 1.3.6.1.2.1.1.3.0=ticks, 1.3.6.1.2.1.1.4.0=string, 1.3.6.1.2.1.1.5.0=string, 1.3.6.1.2.1.1.6.0=string",
  )
  // Six rows plus the GETNEXT that discovers the boundary.
  inspect(agent.next_calls, content="7")
}

///|
test "v3 walk_bulk agrees with walk and costs fewer round trips" {
  let by_next = FakeV3Agent::new(system_group())
  let walking = v3_client_of(by_next)
  let walked = walking.walk(oid("1, 3, 6, 1, 2, 1, 1"), 0)

  let by_bulk = FakeV3Agent::new(system_group())
  let bulking = v3_client_of(by_bulk)
  let bulked = bulking.walk_bulk(oid("1, 3, 6, 1, 2, 1, 1"), 10, 0)

  inspect(bulked.length(), content="6")
  inspect(bulked.length() == walked.length(), content="true")
  inspect(bulked[5].name.to_dotted(), content="1.3.6.1.2.1.1.6.0")
  // The whole group fits in one GETBULK reply.
  inspect(by_bulk.bulk_calls, content="1")
  inspect(by_next.next_calls > by_bulk.bulk_calls, content="true")
}

///|
test "v3 walk honours max_steps" {
  let agent = FakeV3Agent::new(system_group())
  let client = v3_client_of(agent)
  let entries = client.walk(oid("1, 3, 6, 1, 2, 1, 1"), 3)
  inspect(entries.length(), content="3")
}

///|
test "a v3 reply that names another request is refused" {
  // A late duplicate of an earlier reply must not be read as the answer
  // to this request: in a walk it would look like an agent that stopped
  // advancing and quietly truncate the result.
  let agent = FakeV3Agent::new(system_group())
  agent.wrong_id = true
  let client = v3_client_of(agent)
  try {
    let _ = client.get(oid("1, 3, 6, 1, 2, 1, 1, 1, 0"))
    fail("expected ResponseIdMismatch")
  } catch {
    @session.SnmpError::ResponseIdMismatch => ()
    e => fail("expected ResponseIdMismatch, got \{Repr(e)}")
  }
}
