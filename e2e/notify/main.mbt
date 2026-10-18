///|
/// End-to-end notification harness: the agent -> manager direction.
///
/// Two modes, because the two roles need different setups:
///
///   moon run e2e/notify --target js -- send <host> <port>
///     Send notifications to a real receiver (snmptrapd) and check that
///     the acknowledged kind really was acknowledged. Run the receiver
///     with:
///       docker run -d --name trapd -p 16162:162/udp moon-snmp-e2e \
///         snmptrapd -f -Lo -n -c /etc/snmp/snmptrapd.conf
///
///   moon run e2e/notify --target js -- recv <port> <count>
///     Listen for `count` notifications and check each one. Point a
///     real sender at it with snmptrap, which is what CI does.
///
/// The same two roles over v3, where the user and the engine replace the
/// community:
///
///   moon run e2e/notify --target js -- send-v3 <host> <port>
///   moon run e2e/notify --target js -- recv-v3 <port> <count>
///
/// Exits non-zero if any check fails.

///|
const DEFAULT_SEND_HOST : String = "127.0.0.1"

///|
/// The port snmptrapd is published on in the documented docker run.
const DEFAULT_SEND_PORT : Int = 16162

///|
/// The port to listen on in receive mode; the standard trap port is
/// 162, and 16162 is its published equivalent.
const DEFAULT_RECV_PORT : Int = 16162

///|
/// How many notifications receive mode waits for.
const DEFAULT_WANTED : Int = 3

///|
/// How long to wait for each notification, in milliseconds.
const WAIT_MS : Int = 10000

///|
/// The community every notification in this harness uses.
const COMMUNITY : Bytes = b"public"

///|
/// The v3 user, and the passwords the fixture in `e2e/docker` provisions.
const V3_USER : Bytes = b"e2e-trap"

///|
const V3_AUTH_PASSWORD : Bytes = b"trappass"

///|
const V3_PRIV_PASSWORD : Bytes = b"trapprivpass"

///|
/// The engine this harness claims when it *sends* a trap. A trap is
/// authoritative for the sender's engine, so the receiver has to know
/// this id in advance — `snmptrapd.conf` carries the matching
/// `createUser -e` line.
const V3_SENDER_ENGINE_ID : Bytes = b"\x80\x00\x1f\x88\x04moon-snmp-trap"

///|
/// The engine this harness claims when it *receives* an inform. The
/// sender learns it by discovery, so nothing is configured with it in
/// advance.
const V3_RECEIVER_ENGINE_ID : Bytes = b"\x80\x00\x1f\x88\x04moon-snmp-rcv"

///|
/// The v3 user this harness authenticates as.
fn v3_security() -> @snmpv3.Security {
  {
    level: @snmpv3.AuthPriv,
    user: V3_USER,
    auth_protocol: @snmpv3.Sha1,
    auth_password: V3_AUTH_PASSWORD,
    priv_protocol: @snmpv3.Aes128,
    priv_password: V3_PRIV_PASSWORD,
  }
}

///|
/// Our identity as a trap sender: a fixed engine id with a clock that
/// does not move backwards.
fn v3_sender_engine() -> @snmpv3.Engine {
  { id: V3_SENDER_ENGINE_ID, boots: 1, time: 1, }
}

///|
/// Our identity as an inform receiver.
fn v3_receiver_engine() -> @snmpv3.Engine {
  { id: V3_RECEIVER_ENGINE_ID, boots: 1, time: 1, }
}

///|
/// fn main dispatch. The mode comes first so an unknown one fails fast
/// rather than silently doing nothing.
fn main {
  let args = @support.Args::read()
  let mode = args.text(2, "")
  let checks = @support.Checks::new()
  match mode {
    "send" => {
      let host = args.text(3, DEFAULT_SEND_HOST)
      let port = args.number(4, DEFAULT_SEND_PORT)
      println("notify send suite against \{host}:\{port}\n")
      send_suite(checks, host, port) catch {
        e => checks.bad("the suite ran to completion", Repr(e).to_string())
      }
      checks.finish("notify send suite")
    }
    "loopback" => {
      println(
        "notify loopback suite: five notifications, one socket to another\n",
      )
      loopback_suite(checks) catch {
        e => checks.bad("the suite ran to completion", Repr(e).to_string())
      }
      checks.finish("notify loopback suite")
    }
    "recv" => {
      let port = args.number(3, DEFAULT_RECV_PORT)
      let wanted = args.number(4, DEFAULT_WANTED)
      println("notify receive suite on udp/\{port}, expecting \{wanted}\n")
      recv_suite(checks, port, wanted) catch {
        e => checks.bad("the suite ran to completion", Repr(e).to_string())
      }
      checks.finish("notify receive suite")
    }
    "send-v3" => {
      let host = args.text(3, DEFAULT_SEND_HOST)
      let port = args.number(4, DEFAULT_SEND_PORT)
      println("notify v3 send suite against \{host}:\{port}\n")
      send_v3_suite(checks, host, port) catch {
        e => checks.bad("the suite ran to completion", Repr(e).to_string())
      }
      checks.finish("notify v3 send suite")
    }
    "recv-v3" => {
      let port = args.number(3, DEFAULT_RECV_PORT)
      let wanted = args.number(4, DEFAULT_WANTED)
      // A deliberate refusal (a wrong password, say) is counted, not
      // treated as an accident: the caller says how many to expect.
      let refused = args.number(5, 0)
      println("notify v3 receive suite on udp/\{port}, expecting \{wanted}\n")
      recv_v3_suite(checks, port, wanted, refused) catch {
        e => checks.bad("the suite ran to completion", Repr(e).to_string())
      }
      checks.finish("notify v3 receive suite")
    }
    _ => {
      println(
        "usage: e2e/notify [send <host> <port> | recv <port> <count> | send-v3 <host> <port> | recv-v3 <port> <count> | loopback]",
      )
      @support.exit_with(2)
    }
  }
}

///|
/// Send one of each notification shape to a real receiver.
///
/// The three traps can only be checked from the receiver's side, which
/// CI greps for. The inform is different: it is acknowledged, and an
/// acknowledgement is a receiver saying it understood the message, so
/// that check lives here.
fn send_suite(
  checks : @support.Checks,
  host : String,
  port : Int,
) -> Unit raise {
  let socket = @transport.Transport::open(0, 3000)
  println("sending from udp/\{socket.local_port()}")
  let traps = @session.Session::new(
    socket,
    host,
    port,
    @pdu.V2c,
    COMMUNITY,
    2000,
    1,
    100,
  )

  // A v2c trap naming a standard trap OID.
  traps.trap_v2(123456, @mib.link_down(), [
    @pdu.VarBind::new(@mib.if_descr(), @ber.BerValue::OctetString(b"eth0")),
  ])
  checks.ok("trap_v2 with a standard trap OID sent")

  // A v2c trap from a private enterprise, with values of two different
  // types, which is where an encoder bug would show.
  traps.trap_v2(124000, @oid.Oid::parse("1.3.6.1.4.1.99999.1.2.3"), [
    @pdu.VarBind::new(
      @oid.Oid::parse("1.3.6.1.4.1.99999.1.1.1"),
      @ber.BerValue::OctetString(b"vendor payload"),
    ),
    @pdu.VarBind::new(
      @oid.Oid::parse("1.3.6.1.4.1.99999.1.1.2"),
      @ber.BerValue::Integer(42),
    ),
  ])
  checks.ok("trap_v2 from a private enterprise sent")

  // An unsigned value whose top bit is set. It has to travel with a
  // leading zero octet to stay non-negative, and the receiver has to
  // read it back as the large number it is rather than as minus one —
  // which is a bug this harness caught on the way in.
  traps.trap_v2(125000, @mib.authentication_failure(), [
    @pdu.VarBind::new(
      @oid.Oid::parse("1.3.6.1.4.1.99999.1.3.1"),
      @ber.BerValue::Gauge32(0xFFFFFFFF),
    ),
    @pdu.VarBind::new(
      @oid.Oid::parse("1.3.6.1.4.1.99999.1.3.2"),
      @ber.BerValue::Counter32(0x80000000),
    ),
  ])
  checks.ok("trap_v2 with saturated unsigned values sent")

  // A v1 trap: a different body shape, and version 0 on the wire.
  traps.trap_v1(
    @oid.Oid::parse("1.3.6.1.4.1.8072"),
    b"\x7f\x00\x00\x01",
    6, // enterprise-specific
    1101,
    125000,
    [
      @pdu.VarBind::new(
        @oid.Oid::parse("1.3.6.1.4.1.8072.9999.1"),
        @ber.BerValue::OctetString(b"v1 payload"),
      ),
    ],
  )
  checks.ok("trap_v1 sent")

  // The inform: this is the one that proves a real receiver accepted
  // our message, because it only answers one it understood.
  let ack = traps.inform(126000, @mib.warm_start(), [
    @pdu.VarBind::new(@mib.sys_name(), @ber.BerValue::OctetString(b"moon-snmp")),
  ])
  checks.num("inform was acknowledged", ack.length(), 3)
  match ack.get(1) {
    Some(vb) =>
      match vb.value {
        @ber.BerValue::ObjectIdentifier(o) =>
          checks.text(
            "the acknowledgement echoes the trap OID",
            o.to_dotted(),
            @mib.warm_start().to_dotted(),
          )
        _ =>
          checks.bad(
            "the acknowledgement echoes the trap OID", "value was not an OID",
          )
      }
    None =>
      checks.bad("the acknowledgement echoes the trap OID", "no varbind 1")
  }

  // A second inform, so the request-id allocation across notifications
  // is exercised: the receiver must answer this one too.
  let ack2 = traps.inform(127000, @mib.cold_start(), [])
  checks.num("a second inform was acknowledged", ack2.length(), 2)

  socket.close()
}

///|
/// Listen for notifications and check each one.
///
/// Every notification is checked the same way regardless of who sent
/// it: it must be one of the three shapes, name what it is about, and
/// carry an uptime. An inform must also have been acknowledged — the
/// counter is how this side knows the reply went out.
fn recv_suite(checks : @support.Checks, port : Int, wanted : Int) -> Unit raise {
  let socket = @transport.Transport::open(port, 3000)
  println("listening on udp/\{socket.local_port()}")
  let receiver = @session.Receiver::new(socket, Some(COMMUNITY))

  let mut seen_v2c = 0
  let mut seen_v1 = 0
  let mut seen_inform = 0
  let mut got = 0
  while got < wanted {
    let notification = receiver.recv(WAIT_MS) catch {
      @session.SnmpError::NoResponse => {
        checks.bad(
          "all expected notifications arrived",
          "gave up after \{got} of \{wanted}",
        )
        break
      }
      e => {
        checks.bad("receive", Repr(e).to_string())
        break
      }
    }
    got = got + 1
    let label = "\{got}"
    println(
      "\n[\{got}] from \{notification.source_addr}:\{notification.source_port}",
    )
    for vb in notification.varbinds() {
      println("     \{vb.name.to_dotted()} = \{@mib.format_value(vb.value)}")
    }

    // Every notification names itself, whichever shape it has.
    let naming = notification.trap_oid()
    checks.that(
      "notification \{label} names what it is about",
      naming is Some(_),
    )
    match naming {
      Some(o) => println("     -> \{o.to_dotted()}")
      None => ()
    }
    // The origin has to be right, or an acknowledgement could not be
    // addressed.
    checks.that(
      "notification \{label} reports its origin",
      notification.source_addr != "",
    )
    // The uniform uptime accessor must work for all three shapes.
    checks.that(
      "notification \{label} has a readable uptime",
      notification.uptime() is Some(_),
    )

    match notification.kind {
      @session.TrapV2 => {
        seen_v2c = seen_v2c + 1
        checks.that("notification \{label} is a v2c trap", true)
      }
      @session.Inform => {
        seen_inform = seen_inform + 1
        checks.that("notification \{label} is an inform", true)
        // An inform that arrived but was not answered would leave the
        // sender retransmitting; the counter catches it here rather
        // than as a mystery failure in whatever sent it.
        checks.num(
          "inform \{label} was acknowledged",
          receiver.unacknowledged(),
          0,
        )
      }
      @session.TrapV1 => {
        seen_v1 = seen_v1 + 1
        // A v1 trap has no trap OID of its own; the accessor must have
        // translated the numeric code into one.
        checks.that(
          "notification \{label} is a v1 trap that translated to an OID",
          true,
        )
        match notification.trap_v1() {
          Some(t) =>
            checks.that(
              "v1 trap \{label} has a four-octet agent address",
              t.agent_addr.length() == 4,
            )
          None => checks.bad("v1 trap \{label} body", "missing")
        }
      }
    }
  }

  checks.num("all expected notifications arrived", got, wanted)
  checks.num("nothing was rejected", receiver.rejected(), 0)
  checks.num("nothing was left unacknowledged", receiver.unacknowledged(), 0)
  checks.that(
    "the run covered all three notification shapes",
    seen_v2c > 0 && seen_v1 > 0 && seen_inform > 0,
  )
  println(
    "\ncounts: v2c traps \{seen_v2c}, v1 traps \{seen_v1}, informs \{seen_inform}",
  )
  socket.close()
}

///|
/// Send v3 notifications to a real receiver.
///
/// The trap can only be checked from the receiver's side, so CI greps
/// snmptrapd's log for it. The inform is checked here: an
/// acknowledgement means the receiver verified our signature, decrypted
/// the message and understood it — the strongest thing this side can
/// observe.
fn send_v3_suite(
  checks : @support.Checks,
  host : String,
  port : Int,
) -> Unit raise {
  let socket = @transport.Transport::open(0, 3000)
  println("sending v3 from udp/\{socket.local_port()}")
  let client = @session.V3Client::new(
    socket,
    host,
    port,
    v3_security(),
    2000,
    1,
  )
  client.set_local_engine(v3_sender_engine())

  // A trap OID of our own, so the receiver's log line cannot be confused
  // with the v2c suite's linkDown.
  client.trap(131000, @oid.Oid::parse("1.3.6.1.4.1.99999.3.1"), [
    @pdu.VarBind::new(@mib.if_descr(), @ber.BerValue::OctetString(b"eth0")),
  ])
  checks.ok("a v3 authPriv trap sent")

  let ack = client.inform(132000, @mib.warm_start(), [
    @pdu.VarBind::new(@mib.sys_name(), @ber.BerValue::OctetString(b"moon-snmp")),
  ])
  checks.num("the v3 authPriv inform was acknowledged", ack.length(), 3)
  match ack.get(1) {
    Some(vb) =>
      match vb.value {
        @ber.BerValue::ObjectIdentifier(o) =>
          checks.text(
            "the acknowledgement echoes the trap OID",
            o.to_dotted(),
            @mib.warm_start().to_dotted(),
          )
        _ =>
          checks.bad(
            "the acknowledgement echoes the trap OID", "value was not an OID",
          )
      }
    None =>
      checks.bad("the acknowledgement echoes the trap OID", "no varbind 1")
  }
  socket.close()
}

///|
/// Listen for v3 notifications from a real sender.
///
/// A v3 trap is authoritative for the *sender's* engine, so nothing is
/// configured here about who will call: the receiver learns the engine
/// from the message and localizes the key for it. An inform is the
/// other way round — the sender discovers *our* engine first — which is
/// what `discoveries()` counts.
fn recv_v3_suite(
  checks : @support.Checks,
  port : Int,
  wanted : Int,
  refused : Int,
) -> Unit raise {
  let socket = @transport.Transport::open(port, 3000)
  println("listening on udp/\{socket.local_port()}")
  let receiver = @session.Receiver::v3(
    socket,
    v3_receiver_engine(),
    v3_security(),
  )
  let mut got = 0
  let mut traps = 0
  let mut informs = 0
  while got < wanted {
    let notification = receiver.recv(WAIT_MS) catch {
      @session.SnmpError::NoResponse => {
        checks.bad(
          "all expected v3 notifications arrived",
          "gave up after \{got} of \{wanted}",
        )
        break
      }
      e => {
        checks.bad("receive", Repr(e).to_string())
        break
      }
    }
    got = got + 1
    let label = "\{got}"
    println(
      "\n[\{got}] \{kind_name(notification.kind)} from \{notification.source_addr}:\{notification.source_port}",
    )
    for vb in notification.varbinds() {
      println("     \{vb.name.to_dotted()} = \{@mib.format_value(vb.value)}")
    }
    checks.that(
      "v3 notification \{label} arrived over v3",
      notification.version == @pdu.V3,
    )
    match notification.v3 {
      Some(info) => {
        checks.text(
          "v3 notification \{label} names the user it authenticated as",
          @utf8.decode_lossy(info.user),
          @utf8.decode_lossy(V3_USER),
        )
        checks.that(
          "v3 notification \{label} was authenticated and encrypted",
          info.level == @snmpv3.AuthPriv,
        )
        checks.that(
          "v3 notification \{label} names the engine it was scoped to",
          info.engine_id.length() > 0,
        )
        let context_owner = if info.context_engine_id == v3_receiver_engine().id {
          "this receiver"
        } else if info.context_engine_id == info.engine_id {
          "the sending engine"
        } else {
          "neither"
        }
        println(
          "     context engine: \{context_owner}, name \"\{@utf8.decode_lossy(info.context_name)}\"",
        )
      }
      None =>
        checks.bad("v3 notification \{label} carries a v3 context", "missing")
    }
    checks.that(
      "v3 notification \{label} names what it is about",
      notification.trap_oid() is Some(_),
    )
    checks.that(
      "v3 notification \{label} has a readable uptime",
      notification.uptime() is Some(_),
    )
    match notification.kind {
      @session.TrapV2 => {
        traps = traps + 1
        checks.that("v3 notification \{label} is a trap", true)
      }
      @session.Inform => {
        informs = informs + 1
        checks.that("v3 notification \{label} is an inform", true)
        checks.num(
          "v3 inform \{label} was acknowledged",
          receiver.unacknowledged(),
          0,
        )
      }
      @session.TrapV1 =>
        checks.bad(
          "v3 notification \{label} is a v1 trap",
          "v1 cannot travel in v3",
        )
    }
  }
  checks.num("all expected v3 notifications arrived", got, wanted)
  checks.num(
    "only the deliberate refusals were rejected",
    receiver.rejected(),
    refused,
  )
  checks.num("nothing was left unacknowledged", receiver.unacknowledged(), 0)
  checks.that(
    "the inform sender discovered our engine",
    receiver.discoveries() >= 1,
  )
  checks.that(
    "the run covered a v3 trap and a v3 inform",
    traps > 0 && informs > 0,
  )
  println("\ncounts: v3 traps \{traps}, v3 informs \{informs}")
  socket.close()
}

///|
/// A short name for a kind, so a sequence can be compared as text.
fn kind_name(kind : @session.NotificationKind) -> String {
  match kind {
    @session.TrapV1 => "trap-v1"
    @session.TrapV2 => "trap-v2"
    @session.Inform => "inform"
  }
}

///|
/// Send five notifications from one socket to another **in this
/// process**, with nothing between them, and check that all five arrive
/// in the order they were sent.
///
/// This is the regression check for two bugs in the transport bridge
/// that only a burst exposes:
///
///   * when a send travelled through the shared buffer, the second send
///     overwrote the first before the worker read it, so a datagram
///     arrived twice and another not at all;
///   * when the receive side held a single datagram, everything after
///     the first of a burst was dropped.
///
/// The shapes alternate so that a clobbered or coalesced send changes
/// the sequence, not merely the count. It needs no docker and no second
/// process, so it runs anywhere.
fn loopback_suite(checks : @support.Checks) -> Unit raise {
  let receiving_socket = @transport.Transport::open(0, 3000)
  let port = receiving_socket.local_port()
  println("receiver on udp/\{port}")
  let sending_socket = @transport.Transport::open(0, 3000)
  let sender = @session.Session::new(
    sending_socket,
    "127.0.0.1",
    port,
    @pdu.V2c,
    COMMUNITY,
    WAIT_MS,
    0,
    500,
  )
  let receiver = @session.Receiver::new(receiving_socket, Some(COMMUNITY))

  // Back to back, no sleeping: that is the whole point.
  sender.trap_v2(1, @mib.link_down(), [
    @pdu.VarBind::new(@mib.if_descr(), @ber.BerValue::OctetString(b"eth0")),
  ])
  sender.trap_v1(
    @oid.Oid::parse("1.3.6.1.4.1.8072"),
    b"\x7f\x00\x00\x01",
    2,
    0,
    10,
    [],
  )
  sender.trap_v2(2, @mib.link_up(), [])
  sender.trap_v1(
    @oid.Oid::parse("1.3.6.1.4.1.8072"),
    b"\x7f\x00\x00\x01",
    3,
    0,
    20,
    [],
  )
  sender.trap_v2(3, @mib.cold_start(), [])

  let wanted : Array[String] = [
    "trap-v2", "trap-v1", "trap-v2", "trap-v1", "trap-v2",
  ]
  let got : Array[String] = []
  for _ in 0..<wanted.length() {
    let notification = receiver.recv(WAIT_MS)
    got.push(kind_name(notification.kind))
  }
  checks.text(
    "five back-to-back notifications arrive, in order",
    got.join(","),
    wanted.join(","),
  )
  checks.num(
    "the receiving socket dropped nothing",
    receiving_socket.dropped_datagrams(),
    0,
  )
  checks.num("the receiver rejected nothing", receiver.rejected(), 0)

  // A datagram handed to the socket and then immediately closed must
  // still go out. Sending is asynchronous, so a close that terminates
  // the worker at once silently loses whatever is in flight — which is
  // exactly how an acknowledgement to an inform went missing.
  let last_socket = @transport.Transport::open(0, 3000)
  let last_port = last_socket.local_port()
  let brief_tx = @transport.Transport::open(0, 3000)
  let brief = @session.Session::new(
    brief_tx,
    "127.0.0.1",
    last_port,
    @pdu.V2c,
    COMMUNITY,
    WAIT_MS,
    0,
    900,
  )
  brief.trap_v2(9, @mib.link_up(), [])
  brief_tx.close()
  let last_receiver = @session.Receiver::new(last_socket, Some(COMMUNITY))
  let last = last_receiver.recv(WAIT_MS)
  match last.trap_oid() {
    Some(o) =>
      checks.text(
        "a datagram sent just before close still arrives",
        o.to_dotted(),
        @mib.link_up().to_dotted(),
      )
    None =>
      checks.bad(
        "a datagram sent just before close still arrives", "no trap OID",
      )
  }
  last_socket.close()

  // IPv6, the same way: two sockets and one datagram. A socket belongs to
  // one family, so this is the only thing that proves the other family
  // works — a v4 socket cannot reach `::1` and a v6 one cannot reach a
  // dotted-decimal address.
  ipv6_round_trip(checks)

  receiving_socket.close()
  sending_socket.close()
}

///|
/// One datagram across an IPv6 loopback.
///
/// A host without IPv6 is a skip, not a failure: the point is to prove
/// that when the platform has it, this library can use it. The reason is
/// printed either way, so a regression here is not mistaken for a host
/// without v6.
fn ipv6_round_trip(checks : @support.Checks) -> Unit {
  let receiving = @transport.Transport::open_ipv6(0, 3000) catch {
    e => {
      println("       (no IPv6 loopback here: \{Repr(e)} — skipped)")
      return
    }
  }
  let port = receiving.local_port()
  let sending = @transport.Transport::open_ipv6(0, 3000) catch {
    e => {
      checks.bad("a second IPv6 socket opens", Repr(e).to_string())
      receiving.close()
      return
    }
  }
  let outcome = try {
    sending.send("::1", port, b"v6")
    receiving.recv(2000)
  } catch {
    @transport.TransportError::Timeout => {
      checks.bad("a datagram crosses the IPv6 loopback", "timeout")
      sending.close()
      receiving.close()
      return
    }
    e => {
      checks.bad("a datagram crosses the IPv6 loopback", Repr(e).to_string())
      sending.close()
      receiving.close()
      return
    }
  }
  checks.text(
    "an IPv6 datagram carries its payload",
    @utf8.decode_lossy(outcome.data),
    "v6",
  )
  // The address is what a receiver prints as a notification's origin, so
  // it has to be the v6 text rather than an empty string.
  checks.text("the IPv6 sender's address is reported", outcome.from_addr, "::1")
  sending.close()
  receiving.close()
}
