///|
/// End-to-end query suite: drives a real net-snmp agent through this
/// library and checks what comes back.
///
///   docker build -t moon-snmp-e2e e2e/docker
///   docker run -d --name snmpd -p 16161:161/udp moon-snmp-e2e
///   moon run e2e/query --target js -- 127.0.0.1 16161
///
/// Exits non-zero if any check fails, which is what CI reads. Host and
/// port default to the command above, so a bare run works.

///|
const DEFAULT_HOST : String = "127.0.0.1"

///|
const DEFAULT_PORT : Int = 16161

///|
/// How long to wait for one reply, in milliseconds.
const TIMEOUT_MS : Int = 2000

///|
/// How many times to retransmit before giving up.
const RETRIES : Int = 1

///|
/// Where the good session's request ids start. Distinct from the bad
/// session's below, so a late reply cannot be matched to the wrong
/// session when both share one socket.
const GOOD_ID_BASE : Int = 42000

///|
/// Where the wrong-community session's ids start.
const BAD_ID_BASE : Int = 9000

///|
/// How many times a character occurs in a string.
fn count_char(s : String, want : Char) -> Int {
  let mut n = 0
  for c in s {
    if c == want {
      n = n + 1
    }
  }
  n
}

///|
/// Whether an OID's text is inside the walk's subtree. A text prefix is
/// good enough here because the harness only uses it on names an agent
/// produced, where the arcs are already canonical.
fn under(name : @oid.Oid, root : @oid.Oid) -> Bool {
  root.is_prefix_of(name)
}

///|
/// The list of OIDs of a walk, for comparing two walks.
fn walk_names(entries : Array[@session.WalkEntry]) -> Array[String] {
  let out : Array[String] = []
  for e in entries {
    out.push(e.name.to_dotted())
  }
  out
}

///|
fn main {
  let args = @support.Args::read()
  let host = args.text(2, DEFAULT_HOST)
  let port = args.number(3, DEFAULT_PORT)
  println("query suite against \{host}:\{port}\n")
  let checks = @support.Checks::new()
  run_suite(checks, host, port) catch {
    e => checks.bad("the suite ran to completion", Repr(e).to_string())
  }
  checks.finish("query suite")
}

///|
/// The checks themselves.
///
/// Anything that raises — an agent that is not there, a timeout — ends
/// the suite early; `main` records that as the failure it is, so CI
/// shows which check the agent died on rather than a stack trace.
fn run_suite(checks : @support.Checks, host : String, port : Int) -> Unit raise {
  // One socket shared by both sessions, which is how a real program
  // uses this: a client is a conversation, not a socket.
  let socket = @transport.Transport::open(0, 3000)
  let session = @session.Session::new(
    socket,
    host,
    port,
    @pdu.V2c,
    b"public",
    TIMEOUT_MS,
    RETRIES,
    GOOD_ID_BASE,
  )

  // 1. GET: the liveness probe every SNMP tool starts with.
  let descr = session.get(@mib.sys_descr())
  let descr_text = match descr.value {
    @ber.BerValue::OctetString(b) => @utf8.decode_lossy(b)
    _ => ""
  }
  checks.that("get sysDescr.0 returns a value", descr_text.length() > 0)
  checks.text(
    "get answers under the OID it was asked for",
    descr.name.to_dotted(),
    @mib.sys_descr().to_dotted(),
  )
  println("       sysDescr.0 = \{descr_text}")

  // 2. GET with several OIDs: one round trip, answers in request order.
  let many = session.get_many([
    @mib.sys_up_time(),
    @mib.sys_name(),
    @mib.sys_contact(),
  ])
  checks.num("get_many returns one varbind per OID", many.length(), 3)
  checks.text(
    "get_many keeps the requested order",
    match many.get(1) {
      Some(vb) => vb.name.to_dotted()
      None => ""
    },
    @mib.sys_name().to_dotted(),
  )
  checks.text(
    "sysName.0 is the configured name",
    match many.get(1) {
      Some(vb) =>
        match vb.value {
          @ber.BerValue::OctetString(b) => @utf8.decode_lossy(b)
          _ => ""
        }
      None => ""
    },
    "moon-snmp-test-agent",
  )
  checks.text(
    "sysContact.0 is the configured contact",
    match many.get(2) {
      Some(vb) =>
        match vb.value {
          @ber.BerValue::OctetString(b) => @utf8.decode_lossy(b)
          _ => ""
        }
      None => ""
    },
    "dev@example.com",
  )

  // 3. sysUpTime.0 must be a TimeTicks, and the formatter must give it
  //    the shape a human reads.
  match many.get(0) {
    Some(vb) =>
      match vb.value {
        @ber.BerValue::TimeTicks(ticks) => {
          checks.that("sysUpTime.0 is a TimeTicks", true)
          let rendered = @mib.format_time_ticks(ticks)
          let shaped = count_char(rendered, ':') == 2 &&
            count_char(rendered, '.') == 1 &&
            rendered.length() >= 10
          checks.that("format_time_ticks gives H:MM:SS.hh", shaped)
          println("       sysUpTime.0 = \{rendered} (\{ticks} ticks)")
        }
        _ => checks.bad("sysUpTime.0 is a TimeTicks", "value was not TimeTicks")
      }
    None => checks.bad("sysUpTime.0 is a TimeTicks", "no varbind returned")
  }

  // 4. GETNEXT steps to the lexicographic successor.
  let next = session.get_next(@mib.sys_descr())
  checks.text(
    "get_next from sysDescr.0 lands on sysObjectID.0",
    next.name.to_dotted(),
    @mib.sys_object_id().to_dotted(),
  )

  // 5. GETBULK returns a run of successors in one round trip.
  let bulk = session.get_bulk([@mib.system()], 0, 10)
  checks.at_least("get_bulk returns a run of successors", bulk.length(), 8)
  let mut increasing = true
  let mut i = 1
  while i < bulk.length() {
    if bulk[i].name.compare(bulk[i - 1].name) <= 0 {
      increasing = false
    }
    i = i + 1
  }
  checks.that("get_bulk returns them in lexicographic order", increasing)

  // 6. A GET for something absent: v2c answers with the noSuchObject
  //    exception as a *value*, not with an error status (RFC 3416
  //    §4.2.1). Getting this wrong is what makes a missing OID look
  //    like a protocol failure.
  let missing_oid = @oid.Oid::parse("1.3.6.1.2.1.1.99.0")
  let missing = session.get(missing_oid)
  match missing.value {
    @ber.BerValue::Tagged(tag, _) =>
      checks.num("a missing OID comes back as noSuchObject", tag, 0x80)
    other =>
      checks.bad(
        "a missing OID comes back as noSuchObject",
        Repr(other).to_string(),
      )
  }

  // 7. GETNEXT from the last OID in the MIB reports endOfMibView rather
  //    than wrapping around.
  let past_end = session.get_next(@oid.Oid::parse("1.3.6.1.6.3.9999"))
  match past_end.value {
    @ber.BerValue::Tagged(tag, _) =>
      checks.num("stepping past the end reports endOfMibView", tag, 0x82)
    other =>
      checks.bad(
        "stepping past the end reports endOfMibView",
        Repr(other).to_string(),
      )
  }

  // 8. WALK the system group: every entry under the root, in order.
  let walked = session.walk(@mib.system(), 0)
  checks.at_least(
    "walk of the system group finds its scalars",
    walked.length(),
    8,
  )
  let mut all_inside = true
  let mut ascending = true
  let mut previous : @oid.Oid? = None
  for entry in walked {
    if !under(entry.name, @mib.system()) {
      all_inside = false
    }
    match previous {
      Some(p) => if entry.name.compare(p) <= 0 { ascending = false }
      None => ()
    }
    previous = Some(entry.name)
  }
  checks.that("every walked entry is inside the subtree", all_inside)
  checks.that("walk never repeats or goes backwards", ascending)
  checks.text(
    "walk starts at the group's first scalar",
    match walked.get(0) {
      Some(e) => e.name.to_dotted()
      None => ""
    },
    @mib.sys_descr().to_dotted(),
  )

  // 9. WALKBULK must agree with WALK entry for entry. Two independent
  //    implementations of the same traversal, checked against each
  //    other on real data.
  let bulk_walked = session.walk_bulk(@mib.system(), 10, 0)
  checks.num(
    "walk_bulk finds as many entries as walk",
    bulk_walked.length(),
    walked.length(),
  )
  checks.that(
    "walk_bulk returns the same OIDs in the same order",
    walk_names(bulk_walked) == walk_names(walked),
  )
  // A machine-readable line, so CI can compare our count with what
  // net-snmp's own snmpwalk finds for the same subtree. Kept separate
  // from the check output because it is read by a script, not a person.
  println("walk system: \{walked.length()} entries")

  // 10. Walking a scalar's own instance returns just that instance,
  //     which is what `snmpwalk <scalar>` prints.
  let scalar_walk = session.walk(@mib.sys_name(), 0)
  checks.num(
    "walk of a scalar instance returns one entry",
    scalar_walk.length(),
    1,
  )
  checks.text(
    "the scalar walk names the scalar it was given",
    match scalar_walk.get(0) {
      Some(e) => e.name.to_dotted()
      None => ""
    },
    @mib.sys_name().to_dotted(),
  )

  // 11. Walking a table column returns rows indexed by the table's
  //     index, so the names must all sit under the column.
  let column = session.walk(@mib.if_descr(), 0)
  checks.at_least(
    "walk of the ifDescr column finds interfaces",
    column.length(),
    1,
  )
  let mut column_inside = true
  for entry in column {
    if !under(entry.name, @mib.if_descr()) {
      column_inside = false
    }
  }
  checks.that("every column entry sits under the column OID", column_inside)
  for entry in column {
    println(
      "       \{entry.name.to_dotted()} = \{@mib.format_value(entry.value)}",
    )
  }

  // 12. Walking a subtree that does not exist yields nothing, and
  //     terminates rather than running to the end of the MIB.
  let empty_walk = session.walk(@oid.Oid::parse("1.3.6.1.2.1.1.99"), 0)
  checks.num("walking an empty subtree yields nothing", empty_walk.length(), 0)

  // 13. `max_steps` bounds the work.
  let bounded = session.walk(@mib.system(), 2)
  checks.num("walk honours max_steps", bounded.length(), 2)

  // 14. Consecutive requests must not reuse a request id (RFC 3416
  //     §4.1), or a slow reply could be matched to the wrong request.
  //     The harness sees the counter the session stamps into each
  //     request; that it reaches the wire is covered by `e2e/notify`,
  //     which reads the request id out of what a peer received.
  let id_first = session.take_request_id()
  let id_second = session.take_request_id()
  checks.that("request ids advance between requests", id_second > id_first)

  // 15. A wrong community is dropped in silence (RFC 1157 §4.1), so the
  //     only observable outcome is a timeout. A library that reported
  //     this as a decode error would be guessing.
  let bad = @session.Session::new(
    socket,
    host,
    port,
    @pdu.V2c,
    b"not-the-community",
    500,
    1,
    BAD_ID_BASE,
  )
  let mut timed_out = false
  try {
    let _ = bad.get(@mib.sys_descr())
  } catch {
    @session.SnmpError::NoResponse => timed_out = true
    _ => ()
  }
  checks.that("a wrong community times out instead of answering", timed_out)

  // 16. A v1 session still reads a v2c agent: version 1 requests are
  //     what an old device needs, and the agent here answers both.
  let v1_read = session.request_versioned(
    @pdu.V1,
    @pdu.Pdu::request(@pdu.GetRequest, 0, [
      @pdu.VarBind::new(@mib.sys_name(), @ber.BerValue::Null),
    ]),
  )
  checks.num("a v1 GET still returns an answer", v1_read.length(), 1)

  socket.close()
}
