///|
/// Listen for traps and informs.
///
///   moon run examples/trap_listener
///   moon run examples/trap_listener -- 1162 monitoring
///
/// Binds the standard trap port and prints what arrives until it is
/// interrupted. Everything about a notification is worth showing at least
/// once: where it came from, what it is about, the sender's uptime, and
/// the var-binds. A listener is the half of SNMP that does not ask
/// questions, so it also has counters for what it refused and what it
/// failed to answer.

///|
/// How the program was told to behave.
struct Settings {
  port : Int
  community : Bytes
  /// How long to wait for one notification before deciding to stop, in
  /// milliseconds. Zero means listen forever.
  idle_timeout_ms : Int
}

///|
fn main {
  let cli = @common.Cli::read()
  let settings : Settings = {
    port: cli.number(2, 162),
    community: @utf8.encode(cli.text(3, "public")),
    // A default that lets the program be run and finish on its own,
    // which is what makes it usable in a test as well as by hand.
    idle_timeout_ms: cli.number(4, 30000),
  }
  println(
    "listening on udp/\{settings.port} for community \"\{@utf8.decode_lossy(settings.community)}\"",
  )
  println(
    "(will stop after \{(settings.idle_timeout_ms / 1000)}s with nothing arriving)\n",
  )
  listen(settings)
}

///|
/// Bind the port and print every notification until the listener goes
/// quiet.
fn listen(settings : Settings) -> Unit {
  // A receiver binds a known port, because that is where senders have
  // been told to send. Note that 162 needs privileges on some systems;
  // any port will do for testing, and the sender just has to agree.
  let socket = @transport.Transport::open(settings.port, 3000) catch {
    @transport.TransportError::NotOpen => {
      println(
        "could not bind udp/\{settings.port}. Something else is listening there, or the port needs privileges.",
      )
      @common.fail(1)
      return
    }
    e => {
      println("could not open a socket: \{Repr(e)}")
      @common.fail(1)
      return
    }
  }
  // Naming the community makes this a receiver rather than an open door:
  // anything else is dropped without a reply, which is what RFC 1157
  // §4.1 asks for and what keeps a stranger from using the listener as a
  // mirror. Pass an empty community to accept anything.
  let receiver = @session.Receiver::new(
    socket,
    if @utf8.decode_lossy(settings.community) == "" {
      None
    } else {
      Some(settings.community)
    },
  )

  let mut seen = 0
  while true {
    // A timeout here means the listener has gone quiet, not that
    // anything is wrong: a trap receiver spends most of its life
    // waiting. Real deployments would keep going; this one stops so the
    // example terminates.
    let notification = receiver.recv(settings.idle_timeout_ms) catch {
      @session.SnmpError::NoResponse => {
        println("\n(no notifications for a while)")
        break
      }
      e => {
        println("receive failed: \{Repr(e)}")
        break
      }
    }
    seen = seen + 1
    report(seen, notification)
  }

  println("")
  println("accepted \{receiver.accepted()}")
  println("rejected \{receiver.rejected()}")
  println("informs not acknowledged \{receiver.unacknowledged()}")
  if socket.dropped_datagrams() > 0 {
    // Worth shouting about: it means the socket could not keep up or a
    // sender used an oversized datagram, and notifications were lost
    // before this program ever saw them.
    println("dropped by the socket \{socket.dropped_datagrams()}")
  }
  socket.close()
}

///|
fn report(number : Int, notification : @session.Notification) -> Unit {
  let kind = match notification.kind {
    @session.TrapV1 => "trap v1"
    @session.TrapV2 => "trap v2c"
    @session.Inform => "inform"
  }
  println(
    "--- \{number}: \{kind} from \{notification.source_addr}:\{notification.source_port}",
  )
  match notification.trap_oid() {
    Some(oid) => println("    what      \{oid.to_dotted()}")
    None => println("    what      (the sender named nothing)")
  }
  match notification.uptime() {
    Some(ticks) =>
      println("    uptime    \{@mib.format_time_ticks_full(ticks)}")
    None => println("    uptime    (not sent)")
  }
  // An inform was acknowledged by the receiver before this function was
  // called, which is the whole point of sending one: the sender now
  // knows it got here.
  if notification.kind == @session.Inform {
    println("    reply     acknowledged")
  }
  // A v1 trap carries fields a v2c one does not, so show them when they
  // are there rather than pretending the shapes are the same.
  match notification.trap_v1() {
    Some(body) => {
      println("    enterprise    \{body.enterprise.to_dotted()}")
      println("    agent address \{@mib.format_ip_address(body.agent_addr)}")
      println("    generic/specific \{body.generic_trap}/\{body.specific_trap}")
    }
    None => ()
  }
  println("    values")
  for vb in notification.varbinds() {
    println("      \{vb.name.to_dotted()} = \{@mib.format_value(vb.value)}")
  }
}
