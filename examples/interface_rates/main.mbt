///|
/// Sample the interface counters twice and print the rates.
///
///   moon run examples/interface_rates
///   moon run examples/interface_rates -- 192.0.2.10 public 161 5
///
/// `ifInOctets` and `ifOutOctets` are Counter32: octets since the
/// interface came up, not a rate. A rate is two reads and a division, and
/// two things make it wrong if they are not handled: the counter wraps at
/// 2^32 — a busy 10G port does that in under four seconds — and the
/// interface list can change between the reads. The first is handled in
/// `@mib.counter_delta`, the second by dropping interfaces that disappear
/// instead of pairing them with a lookalike.

///|
/// One interface's counters, as one sample found them.
struct Counters {
  index : UInt
  descr : String
  in_octets : UInt
  out_octets : UInt
}

///|
/// The same interface, as a rate.
struct Rate {
  index : UInt
  descr : String
  in_bps : Int64
  out_bps : Int64
}

///|
fn main {
  let cli = @common.Cli::read()
  let target = cli.target()
  // Seconds, because that is what a person types; the socket counts
  // milliseconds.
  let interval = cli.number(5, 2)
  println(
    "sampling \{target.host}:\{target.port} over \{interval}s (community \"\{@utf8.decode_lossy(target.community)}\")\n",
  )
  let socket = @transport.Transport::open(0, 3000) catch {
    @transport.TransportError::NotOpen => {
      println("could not open a socket")
      @common.fail(1)
      return
    }
    e => {
      println("could not open a socket: \{Repr(e)}")
      @common.fail(1)
      return
    }
  }
  let session = @session.Session::new(
    socket,
    target.host,
    target.port,
    @pdu.V2c,
    target.community,
    3000,
    1,
    1000,
  )
  let outcome = Some(measure(session, interval)) catch {
    @session.SnmpError::NoResponse => {
      println(
        "no reply. Check the address, the community, and that the agent is running.",
      )
      None
    }
    e => {
      println("sampling failed: \{Repr(e)}")
      None
    }
  }
  socket.close()
  match outcome {
    Some(rates) => print_rates(rates)
    None => @common.fail(1)
  }
}

///|
/// Read the counters, wait, read them again, and turn the difference into
/// a rate.
///
/// The clock is read around the wait so a slow device stretches the
/// interval rather than being reported as faster than it is. The second
/// walk happens after the clock is stopped, which makes the rate a little
/// conservative — the honest direction to be wrong in.
fn measure(
  session : @session.Session[@transport.Transport],
  interval : Int,
) -> Array[Rate] raise {
  let first = sample(session)
  let started = @common.now_ms()
  @common.sleep_ms(interval * 1000)
  let second = sample(session)
  let elapsed_ms = @common.now_ms() - started
  rates_between(first, second, elapsed_ms)
}

///|
/// One pass over the three columns this program needs.
///
/// Three walks rather than one walk of `ifEntry`: the whole table is six
/// columns of data this program would throw away, and a column walk is
/// the shape the library is built for (`walk_bulk` over one column).
fn sample(
  session : @session.Session[@transport.Transport],
) -> Array[Counters] raise {
  let names = session.walk_bulk(@mib.if_descr(), 25, 500)
  let ins = session.walk_bulk(@mib.if_in_octets(), 25, 500)
  let outs = session.walk_bulk(@mib.if_out_octets(), 25, 500)
  let out : Array[Counters] = []
  for entry in ins {
    match last_arc(entry.name) {
      Some(index) =>
        match entry.value {
          @ber.BerValue::Counter32(in_octets) =>
            match counter_at(outs, index) {
              Some(out_octets) =>
                out.push({
                  index,
                  descr: descr_at(names, index),
                  in_octets,
                  out_octets,
                })
              // An interface with an input counter and no output counter
              // is not something to guess about.
              None => ()
            }
          // Anything but a Counter32 means this is not an octet counter,
          // whatever the OID says.
          _ => ()
        }
      None => ()
    }
  }
  out
}

///|
/// The last arc of an OID, which for a table cell is its row index.
fn last_arc(oid : @oid.Oid) -> UInt? {
  let parts = oid.parts()
  if parts.length() == 0 {
    None
  } else {
    Some(parts[parts.length() - 1])
  }
}

///|
fn entry_at(
  entries : Array[@session.WalkEntry],
  index : UInt,
) -> @session.WalkEntry? {
  for e in entries {
    match last_arc(e.name) {
      Some(i) => if i == index { return Some(e) }
      None => ()
    }
  }
  None
}

///|
fn descr_at(names : Array[@session.WalkEntry], index : UInt) -> String {
  match entry_at(names, index) {
    Some(e) =>
      match e.value {
        @ber.BerValue::OctetString(b) => @utf8.decode_lossy(b)
        _ => ""
      }
    None => ""
  }
}

///|
fn counter_at(entries : Array[@session.WalkEntry], index : UInt) -> UInt? {
  match entry_at(entries, index) {
    Some(e) =>
      match e.value {
        @ber.BerValue::Counter32(n) => Some(n)
        _ => None
      }
    None => None
  }
}

///|
fn find_counters(entries : Array[Counters], index : UInt) -> Counters? {
  for e in entries {
    if e.index == index {
      return Some(e)
    }
  }
  None
}

///|
/// Pair up two samples and divide.
fn rates_between(
  first : Array[Counters],
  second : Array[Counters],
  elapsed_ms : Int64,
) -> Array[Rate] {
  let ms = if elapsed_ms <= 0L { 1L } else { elapsed_ms }
  let out : Array[Rate] = []
  for a in first {
    match find_counters(second, a.index) {
      Some(b) => {
        // Octets to bits, then over the time that actually passed.
        // Integer arithmetic throughout: a float here would only add
        // rounding of its own.
        let bits_in = @mib.counter_delta(a.in_octets, b.in_octets).to_int64() *
          8L
        let bits_out = @mib.counter_delta(a.out_octets, b.out_octets).to_int64() *
          8L
        out.push({
          index: a.index,
          descr: a.descr,
          in_bps: bits_in * 1000L / ms,
          out_bps: bits_out * 1000L / ms,
        })
      }
      // The interface went away between the samples; a rate for it would
      // be a rate for a different interface.
      None => ()
    }
  }
  out
}

///|
fn print_rates(rates : Array[Rate]) -> Unit {
  if rates.length() == 0 {
    println(
      "no interface counters came back: an agent that does not implement ifTable, or a device with no interfaces?",
    )
    return
  }
  println(
    "\{@common.pad("index", 5)}  \{@common.pad("interface", 20)}  \{@common.pad_left("in", 12)}  \{@common.pad_left("out", 12)}",
  )
  for r in rates {
    let index = "\{r.index}"
    println(
      "\{@common.pad(index, 5)}  \{@common.pad(r.descr, 20)}  \{@common.pad_left(@mib.format_bit_rate(r.in_bps), 12)}  \{@common.pad_left(@mib.format_bit_rate(r.out_bps), 12)}",
    )
  }
  println("")
  println("\{rates.length()} interfaces")
}
