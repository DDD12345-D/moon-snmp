///|
/// List a device's network interfaces.
///
///   moon run examples/walk_table
///   moon run examples/walk_table -- 192.0.2.10 public 161
///
/// Walks the MIB-II interface table and prints one row per interface.
///
/// The interesting part is the shape of a table on the wire. `ifTable`
/// is indexed by `ifIndex`, and each cell has the OID
/// `ifEntry.<column>.<ifIndex>`. A walk returns cells in lexicographic
/// order, which is column-major: every interface's name, then every
/// interface's type, and so on. So printing a row per interface means
/// regrouping the cells by their trailing arc, in two passes — collect,
/// then assemble. That shape is the same for every MIB table, so it is
/// worth reading once.

///|
/// One cell of the table, as the walk returned it.
struct Cell {
  index : UInt
  column : UInt
  value : @ber.BerValue
}

///|
/// One row, assembled from the cells that share an index.
struct Interface {
  index : UInt
  descr : String
  kind : String
  mtu : String
  speed : String
  status : String
  address : String
}

///|
fn main {
  let cli = @common.Cli::read()
  let target = cli.target()
  println(
    "listing the interfaces of \{target.host}:\{target.port} (community \"\{@utf8.decode_lossy(target.community)}\")\n",
  )
  let outcome = Some(list(target)) catch {
    @session.SnmpError::NoResponse => {
      println(
        "no reply. Check the address, the community, and that the agent is running.",
      )
      None
    }
    e => {
      println("could not list the interfaces: \{Repr(e)}")
      None
    }
  }
  // The socket is closed here rather than inside `list`, so a reply that
  // is still in flight when the work is done is not thrown away.
  match outcome {
    Some(socket) => socket.close()
    None => @common.fail(1)
  }
}

///|
/// Walk the table and print it.
fn list(target : @common.Target) -> @transport.Transport raise {
  let socket = @transport.Transport::open(0, 3000)
  let session = @session.Session::new(
    socket,
    target.host,
    target.port,
    @pdu.V2c,
    target.community,
    2000,
    1,
    1,
  )

  // How many interfaces the device says it has. Worth asking separately:
  // it tells "no interfaces" apart from "the walk went wrong", and it is
  // one cheap GET.
  let reported = session.get(@mib.if_number())
  match reported.value {
    @ber.BerValue::Integer(n) => println("ifNumber = \{n}\n")
    other => println("ifNumber = \{@mib.format_value(other)}\n")
  }

  // `walk_bulk` is the v2c way to read a table. GETBULK returns a run of
  // successors per round trip, so a table costs a handful of requests
  // rather than one per cell. 25 is the batch size; 500 is a ceiling on
  // the whole walk, so a device with an enormous table cannot make this
  // run forever.
  let entries = session.walk_bulk(@mib.if_entry(), 25, 500)

  let cells : Array[Cell] = []
  for entry in entries {
    // `ifEntry.<column>.<ifIndex>`: the last arc is the row, the one
    // before it the column.
    let parts = entry.name.parts()
    if parts.length() < 2 {
      continue
    }
    cells.push({
      index: parts[parts.length() - 1],
      column: parts[parts.length() - 2],
      value: entry.value,
    })
  }

  // The distinct indexes, in the order the walk first mentioned them.
  // Small enough to scan rather than to keep a set of.
  let indexes : Array[UInt] = []
  for cell in cells {
    let mut seen = false
    for known in indexes {
      if known == cell.index {
        seen = true
      }
    }
    if !seen {
      indexes.push(cell.index)
    }
  }

  let rows : Array[Interface] = []
  for index in indexes {
    rows.push({
      index,
      descr: text_at(cells, index, 2),
      kind: type_at(cells, index, 3),
      mtu: raw_at(cells, index, 4),
      speed: speed_at(cells, index, 5),
      status: status_at(cells, index, 8),
      address: address_at(cells, index, 6),
    })
  }

  print_table(rows)
  socket
}

///|
/// The cell at `<column>.<index>`, if the walk brought it back.
fn cell_at(cells : Array[Cell], index : UInt, column : UInt) -> @ber.BerValue? {
  for cell in cells {
    if cell.index == index && cell.column == column {
      return Some(cell.value)
    }
  }
  None
}

///|
/// A column rendered the way the mib package renders its type, or "?" if
/// the device did not send it.
fn raw_at(cells : Array[Cell], index : UInt, column : UInt) -> String {
  match cell_at(cells, index, column) {
    Some(value) => @mib.format_value(value)
    None => "?"
  }
}

///|
/// A column whose value is a string, without the quotes a report does
/// not need.
fn text_at(cells : Array[Cell], index : UInt, column : UInt) -> String {
  match cell_at(cells, index, column) {
    Some(@ber.BerValue::OctetString(b)) => @utf8.decode_lossy(b)
    Some(other) => @mib.format_value(other)
    None => "?"
  }
}

///|
/// ifType is an IANAifType integer, so the bare number tells a reader
/// nothing; the mib formatter names the common ones.
fn type_at(cells : Array[Cell], index : UInt, column : UInt) -> String {
  match cell_at(cells, index, column) {
    Some(@ber.BerValue::Integer(n)) => @mib.format_if_type(n)
    Some(other) => @mib.format_value(other)
    None => "?"
  }
}

///|
/// ifOperStatus is 1 up, 2 down, and so on.
fn status_at(cells : Array[Cell], index : UInt, column : UInt) -> String {
  match cell_at(cells, index, column) {
    Some(@ber.BerValue::Integer(n)) => @mib.format_if_oper_status(n)
    Some(other) => @mib.format_value(other)
    None => "?"
  }
}

///|
/// ifSpeed is a Gauge32 counted in bits per second, which is unreadable
/// as a bare number; a link is described in Mb/s or Gb/s.
fn speed_at(cells : Array[Cell], index : UInt, column : UInt) -> String {
  match cell_at(cells, index, column) {
    Some(@ber.BerValue::Gauge32(bits)) =>
      if bits == 0 {
        // A device is allowed to report zero when it cannot tell.
        "unknown"
      } else if bits == 0xFFFFFFFF {
        // RFC 3635 §3.1.4: the maximum means the bandwidth is either
        // greater than 4.29 Gb/s or not known. Printing "4 Gb/s" would
        // state a number the device did not give.
        ">4 Gb/s"
      } else if bits >= 1000000000 {
        scaled(bits, 1000000000, "Gb/s")
      } else if bits >= 1000000 {
        scaled(bits, 1000000, "Mb/s")
      } else if bits >= 1000 {
        scaled(bits, 1000, "kb/s")
      } else {
        "\{bits} b/s"
      }
    Some(other) => @mib.format_value(other)
    None => "?"
  }
}

///|
/// A bit rate in the given unit, with two decimals when there is a
/// remainder, so that 10750000 is "10.75 Mb/s" rather than a rounded 10.
fn scaled(bits : UInt, unit : UInt, label : String) -> String {
  let whole = bits / unit
  let remainder = bits % unit
  if remainder == 0 {
    "\{whole} \{label}"
  } else {
    // Dividing the unit first keeps the intermediate value inside 32
    // bits: the remainder times 100 would not fit.
    let hundredths = remainder / (unit / 100)
    "\{whole}.\{@common.pad_left(hundredths.to_string(), 2)} \{label}"
  }
}

///|
/// ifPhysAddress is a byte string, usually six octets of MAC address.
fn address_at(cells : Array[Cell], index : UInt, column : UInt) -> String {
  match cell_at(cells, index, column) {
    Some(@ber.BerValue::OctetString(b)) => @mib.format_mac_address(b)
    Some(other) => @mib.format_value(other)
    None => ""
  }
}

///|
/// The columns this program prints, in the order it prints them.
fn column_of(row : Interface) -> Array[String] {
  [
    row.index.to_string(),
    row.descr,
    row.kind,
    row.mtu,
    row.speed,
    row.status,
    row.address,
  ]
}

///|
/// Print the rows as a table, with the widest cell in each column
/// setting the width so nothing wraps.
fn print_table(rows : Array[Interface]) -> Unit {
  let headers : Array[String] = [
    "index", "name", "type", "mtu", "speed", "status", "address",
  ]
  // The first pass measures and the second writes: a value wider than
  // its header has to be known before the header is printed.
  let widths : Array[Int] = []
  for header in headers {
    widths.push(header.length())
  }
  for row in rows {
    let cells = column_of(row)
    for i in 0..<cells.length() {
      if cells[i].length() > widths[i] {
        widths[i] = cells[i].length()
      }
    }
  }

  println(join_row(headers, widths))
  for row in rows {
    println(join_row(column_of(row), widths))
  }
  println("\n\{rows.length()} interface(s)")
}

///|
/// One line of the table, each cell padded to its column width.
fn join_row(cells : Array[String], widths : Array[Int]) -> String {
  let mut line = ""
  for i in 0..<cells.length() {
    line = line + @common.pad(cells[i], widths[i] + 2)
  }
  line
}
