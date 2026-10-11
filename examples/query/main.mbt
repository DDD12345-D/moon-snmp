///|
/// Ask a device who it is.
///
///   moon run examples/query
///   moon run examples/query -- 192.0.2.10 public 161
///
/// Reads the MIB-II system group in one round trip and prints it. This
/// is the smallest useful thing an SNMP client does, and it is also the
/// first thing to try when something is wrong: if this works, the
/// address, the community and the version are all right.

///|
fn main {
  let cli = @common.Cli::read()
  let target = cli.target()
  println(
    "asking \{target.host}:\{target.port} as \"\{@utf8.decode_lossy(target.community)}\"\n",
  )
  let outcome = Some(ask(target)) catch {
    @session.SnmpError::NoResponse => {
      println(
        "no reply. The address, the port, or the community is wrong, or the agent is not running.",
      )
      None
    }
    e => {
      println("the agent answered, but not usefully: \{Repr(e)}")
      None
    }
  }
  match outcome {
    Some(socket) => socket.close()
    None => @common.fail(1)
  }
}

///|
/// One GET for the whole system group, then print it.
///
/// Returns the socket so `main` can close it once the work is done. A
/// socket closed while a reply is still in flight would drop that reply,
/// which is a surprising way to lose an answer.
fn ask(target : @common.Target) -> @transport.Transport raise {
  // A client wants the OS to choose its local port. The timeout and
  // retry count are the two numbers worth thinking about: two seconds
  // and one retry is a sane default for a device on the same network.
  let socket = @transport.Transport::open(0, 3000)
  let session = @session.Session::new(
    socket,
    target.host,
    target.port,
    @pdu.V2c,
    target.community,
    2000, // ms to wait for each reply
    1, // extra attempts after a timeout
    1, // first request id
  )

  // One round trip for six values. Asking for them together is both
  // faster than six GETs and more consistent, because the answers all
  // come from the same instant.
  let varbinds = session.get_many([
    @mib.sys_descr(),
    @mib.sys_object_id(),
    @mib.sys_up_time(),
    @mib.sys_name(),
    @mib.sys_contact(),
    @mib.sys_location(),
  ])

  // The library hands back what the agent sent, in the order it was
  // asked for. Naming the fields is the caller's job, and the MIB
  // constants are what makes it readable instead of a column of dotted
  // numbers.
  for vb in varbinds {
    println(
      "\{@common.pad(name_of(vb.name), 12)} \{@mib.format_value(vb.value)}",
    )
  }
  socket
}

///|
/// A short name for the six OIDs this program asks about.
fn name_of(oid : @oid.Oid) -> String {
  let known : Array[(@oid.Oid, String)] = [
    (@mib.sys_descr(), "sysDescr"),
    (@mib.sys_object_id(), "sysObjectID"),
    (@mib.sys_up_time(), "sysUpTime"),
    (@mib.sys_name(), "sysName"),
    (@mib.sys_contact(), "sysContact"),
    (@mib.sys_location(), "sysLocation"),
  ]
  for entry in known {
    let (candidate, label) = entry
    if oid.compare(candidate) == 0 {
      return label
    }
  }
  oid.to_dotted()
}
