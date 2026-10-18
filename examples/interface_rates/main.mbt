///|
/// Sample the interface counters twice and print the rates.
///
///   moon run examples/interface_rates
///   moon run examples/interface_rates -- 192.0.2.10 public 161 5
///
/// A rate is two reads and a division, and four things make it wrong if
/// they are not handled:
///
///   * the counters wrap. `ifInOctets` is a Counter32, and on a 10G link
///     that is four seconds of traffic — so the 64-bit `ifHCInOctets`
///     columns are read first, and the 32-bit ones are only a fallback for
///     devices that predate `ifXTable` (RFC 2863);
///   * the interface list can change between the reads, so an interface
///     that disappears is dropped rather than paired with a lookalike;
///   * the interval has to be the time that actually passed, not the time
///     the program asked for;
///   * an agent caches its interface table. net-snmp serves `ifTable` from
///     a cache of a few seconds, so two reads a second apart return the
///     same counters and honestly report zero. The default interval is
///     five seconds for that reason, not for round numbers.

///|
/// One interface's counters, as one sample found them.
struct Counters {
  index : UInt
  descr : String
  in_octets : UInt64
  out_octets : UInt64
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
  let interval = cli.number(5, 5)
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
    Some((rates, wide)) => print_rates(rates, wide)
    None => @common.fail(1)
  }
}

///|
/// Read the counters, wait, read them again, and turn the difference into
/// a rate.
///
/// Which pair of columns to read is decided once, from the first sample:
/// an agent that implements `ifXTable` answers the 64-bit walk, and one
/// that does not answers it with nothing.
///
/// The clock is read around the wait so a slow device stretches the
/// interval rather than being reported as faster than it is. The second
/// walk happens after the clock is stopped, which makes the rate a little
/// conservative — the honest direction to be wrong in.
fn measure(
  session : @session.Session[@transport.Transport],
  interval : Int,
) -> (Array[Rate], Bool) raise {
  let mut wide = true
  let mut first = sample(session, wide)
  if first.length() == 0 {
    // No ifXTable on this device: the 32-bit columns are all there is.
    wide = false
    first = sample(session, wide)
  }
  let started = @common.now_ms()
  @common.sleep_ms(interval * 1000)
  let second = sample(session, wide)
  let elapsed_ms = @common.now_ms() - started
  (rates_between(first, second, elapsed_ms, wide), wide)
}

///|
/// One pass over the three columns this program needs.
///
/// Column walks rather than one walk of `ifEntry`: the whole table is
/// dozens of columns of data this program would throw away.
fn sample(
  session : @session.Session[@transport.Transport],
  wide : Bool,
) -> Array[Counters] raise {
  let names = session.walk_bulk(@mib.if_descr(), 25, 500)
  let in_column = if wide {
    @mib.if_hc_in_octets()
  } else {
    @mib.if_in_octets()
  }
  let out_column = if wide {
    @mib.if_hc_out_octets()
  } else {
    @mib.if_out_octets()
  }
  let ins = session.walk_bulk(in_column, 25, 500)
  let outs = session.walk_bulk(out_column, 25, 500)
  let out : Array[Counters] = []
  for entry in ins {
    match last_arc(entry.name) {
      Some(index) =>
        match counter_value(entry.value, wide) {
          Some(in_octets) =>
            match counter_at(outs, index, wide) {
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
          // Anything but the counter type this column should carry means
          // it is not an octet counter, whatever the OID says.
          None => ()
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
/// A counter as a 64-bit value, whichever width the column carries.
fn counter_value(value : @ber.BerValue, wide : Bool) -> UInt64? {
  if wide {
    match value {
      @ber.BerValue::Counter64(n) => Some(n)
      _ => None
    }
  } else {
    match value {
      @ber.BerValue::Counter32(n) => Some(n.to_uint64())
      _ => None
    }
  }
}

///|
fn counter_at(
  entries : Array[@session.WalkEntry],
  index : UInt,
  wide : Bool,
) -> UInt64? {
  match entry_at(entries, index) {
    Some(e) => counter_value(e.value, wide)
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
/// The difference at the width the counter actually has: a 32-bit value
/// promoted to 64 bits still wraps at 32, so the two cannot share one
/// subtraction.
fn counter_delta(earlier : UInt64, later : UInt64, wide : Bool) -> UInt64 {
  if wide {
    @mib.counter64_delta(earlier, later)
  } else {
    @mib.counter_delta(earlier.to_uint(), later.to_uint()).to_uint64()
  }
}

///|
/// Pair up two samples and divide.
fn rates_between(
  first : Array[Counters],
  second : Array[Counters],
  elapsed_ms : Int64,
  wide : Bool,
) -> Array[Rate] {
  let ms = if elapsed_ms <= 0L { 1L } else { elapsed_ms }
  let out : Array[Rate] = []
  for a in first {
    match find_counters(second, a.index) {
      Some(b) => {
        // Octets to bits, then over the time that actually passed.
        // Integer arithmetic throughout: a float here would only add
        // rounding of its own.
        let bits_in = counter_delta(a.in_octets, b.in_octets, wide).reinterpret_as_int64() *
          8L
        let bits_out = counter_delta(a.out_octets, b.out_octets, wide).reinterpret_as_int64() *
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
fn print_rates(rates : Array[Rate], wide : Bool) -> Unit {
  if rates.length() == 0 {
    println(
      "no interface counters came back: an agent that does not implement ifTable, or a device with no interfaces?",
    )
    return
  }
  // Saying which counters were read is the difference between a number
  // and a number a reader can trust.
  let source = if wide {
    "64-bit (ifHCInOctets / ifHCOutOctets)"
  } else {
    "32-bit (ifInOctets / ifOutOctets, wraps every 4 GiB)"
  }
  println("counters  \{source}\n")
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
