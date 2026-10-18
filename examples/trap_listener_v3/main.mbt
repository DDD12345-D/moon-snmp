///|
/// Listen for SNMPv3 traps and informs, as a user.
///
///   moon run examples/trap_listener_v3 -- 1162 monitor authpass privpass
///
/// A v3 notification is not a v2c one with a user bolted on. The engine
/// that is authoritative decides which key the message was signed with,
/// and it is a different engine in each direction: for a trap it is the
/// sender, for an inform it is this listener — which is why an inform
/// sender has to discover this program before it can send anything.
///
/// So the interesting part of a v3 notification is not the var-binds, it
/// is the line that says which engine it came from, which user it was
/// authenticated as, and how well it was protected. That is what this
/// prints.

///|
/// How the program was told to behave.
struct Settings {
  port : Int
  user : Bytes
  auth_password : Bytes
  priv_password : Bytes
  /// How long to wait for one notification before stopping, in
  /// milliseconds.
  idle_timeout_ms : Int
}

///|
/// This listener's own engine: the identity an inform is addressed to.
///
/// A receiver without one can still take traps, but cannot take informs,
/// because it has nothing to tell a sender that asks who it is. A real
/// deployment generates it once and keeps it across restarts — the
/// sender records the clock that belongs to it. A fixed value is the
/// honest thing for an example, and the README says so.
fn local_engine() -> @snmpv3.Engine {
  { id: b"\x80\x00\x1f\x88\x04trap-listen", boots: 1, time: 0, }
}

///|
fn main {
  let cli = @common.Cli::read()
  let user = cli.text(3, "")
  if user == "" {
    println(
      "usage: moon run examples/trap_listener_v3 -- <port> <user> <auth-password> <priv-password> [idle-seconds]",
    )
    println("")
    println(
      "  e.g. moon run examples/trap_listener_v3 -- 1162 monitor authpass privpass 30",
    )
    @common.fail(2)
    return
  }
  let settings : Settings = {
    port: cli.number(2, 1162),
    user: @utf8.encode(user),
    auth_password: @utf8.encode(cli.text(4, "")),
    priv_password: @utf8.encode(cli.text(5, "")),
    // The argument is seconds, because that is what a person types;
    // the receiver counts milliseconds.
    idle_timeout_ms: cli.number(6, 30) * 1000,
  }
  listen(settings)
}

///|
/// Bind the port and print every notification until the listener goes
/// quiet.
fn listen(settings : Settings) -> Unit {
  // 1162 rather than 162 on purpose: the standard trap port needs
  // privileges on most systems, and nothing here depends on the number.
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
  let security : @snmpv3.Security = {
    level: @snmpv3.AuthPriv,
    user: settings.user,
    auth_protocol: @snmpv3.Sha1,
    auth_password: settings.auth_password,
    priv_protocol: @snmpv3.Aes128,
    priv_password: settings.priv_password,
  }
  let engine = local_engine()
  println(
    "listening on udp/\{settings.port} as user \"\{@utf8.decode_lossy(settings.user)}\" (authPriv, SHA-1 + AES-128)",
  )
  println("this engine  \{@mib.hex_string(engine.id)}")
  println(
    "(will stop after \{(settings.idle_timeout_ms / 1000)}s with nothing arriving)\n",
  )
  let receiver = @session.Receiver::v3(socket, engine, security)
  let mut seen = 0
  while true {
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
  // For v3 this is not a curiosity: it counts the senders that asked who
  // this engine is before addressing an inform to it.
  println("engine discoveries answered \{receiver.discoveries()}")
  if socket.dropped_datagrams() > 0 {
    println("dropped by the socket \{socket.dropped_datagrams()}")
  }
  socket.close()
}

///|
fn level_name(level : @snmpv3.SecurityLevel) -> String {
  match level {
    @snmpv3.NoAuthNoPriv => "noAuthNoPriv"
    @snmpv3.AuthNoPriv => "authNoPriv"
    @snmpv3.AuthPriv => "authPriv"
  }
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
  match notification.v3 {
    Some(info) => {
      // The engine id is the point: a trap is scoped to its sender, an
      // inform to this listener, and the key follows the id.
      println("    engine    \{@mib.hex_string(info.engine_id)}")
      println("    user      \{@utf8.decode_lossy(info.user)}")
      println("    level     \{level_name(info.level)}")
      if info.context_name.length() > 0 {
        println("    context   \{@utf8.decode_lossy(info.context_name)}")
      }
    }
    None => println("    security  (v1/v2c, no engine)")
  }
  match notification.trap_oid() {
    Some(oid) => println("    what      \{oid.to_dotted()}")
    None => println("    what      (the sender named nothing)")
  }
  match notification.uptime() {
    Some(ticks) =>
      println("    uptime    \{@mib.format_time_ticks_full(ticks)}")
    None => println("    uptime    (not sent)")
  }
  // The receiver acknowledged an inform before this function was
  // called; the counter says whether that answer could be addressed.
  if notification.kind == @session.Inform {
    println("    reply     acknowledged")
  }
  println("    values")
  for vb in notification.varbinds() {
    println("      \{vb.name.to_dotted()} = \{@mib.format_value(vb.value)}")
  }
}
