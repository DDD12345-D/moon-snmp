///|
/// Human-readable rendering of the SNMP value types, matching what
/// `snmpwalk` prints closely enough to be useful in logs and CLIs.
///
/// The types that carry a unit or an enumerated meaning — TimeTicks,
/// the interface status, the interface type — get one; the plain
/// numeric types are printed with their name so a reader can tell a
/// Gauge32 from a Counter32, which matters because they are all just
/// unsigned 32-bit integers on the wire.

///|
/// Render a `TimeTicks` value (hundredths of a second since the entity
/// came up) as `1:02:03.45`, the way `snmpwalk` does.
pub fn format_time_ticks(ticks : UInt) -> String {
  let total_hundredths = ticks.reinterpret_as_int()
  let hundredths = total_hundredths % 100
  let total_seconds = total_hundredths / 100
  let seconds = total_seconds % 60
  let total_minutes = total_seconds / 60
  let minutes = total_minutes % 60
  let hours = total_minutes / 60
  "\{hours}:\{two_digits(minutes)}:\{two_digits(seconds)}.\{two_digits(hundredths)}"
}

///|
/// Zero-pad to two digits.
fn two_digits(n : Int) -> String {
  if n < 10 {
    "0\{n}"
  } else {
    n.to_string()
  }
}

///|
/// The `ifOperStatus` enumeration (RFC 1213 §6.2.9).
pub fn format_if_oper_status(status : Int) -> String {
  match status {
    1 => "up"
    2 => "down"
    3 => "testing"
    4 => "unknown"
    5 => "dormant"
    6 => "notPresent"
    7 => "lowerLayerDown"
    _ => "unknown(\{status})"
  }
}

///|
/// The `ifAdminStatus` enumeration (RFC 1213 §6.2.8). Same shape as
/// `ifOperStatus` but with `notPresent` where the operational status
/// has `lowerLayerDown`.
pub fn format_if_admin_status(status : Int) -> String {
  match status {
    1 => "up"
    2 => "down"
    3 => "testing"
    _ => "unknown(\{status})"
  }
}

///|
/// A handful of the IANAifType values (RFC 1213 §6.2.2 has the full
/// list). Only the ones a lab or a typical host will actually report
/// are named; everything else prints as its number, which is what
/// `snmpwalk` does for an unknown type too.
pub fn format_if_type(if_type : Int) -> String {
  match if_type {
    1 => "other"
    6 => "ethernetCsmacd"
    18 => "ds1"
    19 => "e1"
    23 => "ppp"
    24 => "softwareLoopback"
    53 => "propVirtual"
    71 => "ieee80211"
    131 => "tunnel"
    135 => "l2vlan"
    136 => "l3ipvlan"
    161 => "ieee8023adLag"
    _ => if_type.to_string()
  }
}

///|
/// Render a Counter32 as `Counter32(1234)`. The wrapper name is kept
/// because the type matters: a counter wraps at 2^32 and its rate is
/// what a monitoring tool cares about, whereas a Gauge is a level.
pub fn format_counter32(n : UInt) -> String {
  "Counter32(\{n})"
}

///|
/// Render a Gauge32 as `Gauge32(1234)`.
pub fn format_gauge32(n : UInt) -> String {
  "Gauge32(\{n})"
}

///|
/// Render a TimeTicks as `Timeticks: (12345) 0:02:03.45`, matching
/// `snmpwalk`'s output shape.
pub fn format_time_ticks_full(ticks : UInt) -> String {
  "Timeticks: (\{ticks}) \{format_time_ticks(ticks)}"
}

///|
/// Render an IPv4 address from its four octets.
pub fn format_ip_address(octets : Bytes) -> String {
  if octets.length() != 4 {
    return "<ip \{octets.length()} octets>"
  }
  let a = octets.at(0).to_uint()
  let b = octets.at(1).to_uint()
  let c = octets.at(2).to_uint()
  let d = octets.at(3).to_uint()
  "\{a}.\{b}.\{c}.\{d}"
}

///|
/// Render a MAC address as `aa:bb:cc:dd:ee:ff`. Used for
/// `ifPhysAddress`, which is an OctetString that is usually six octets
/// but can be empty on an interface with no link-layer address.
pub fn format_mac_address(octets : Bytes) -> String {
  if octets.length() == 0 {
    return ""
  }
  let parts : Array[String] = []
  for i in 0..<octets.length() {
    let b = octets.at(i).to_uint().reinterpret_as_int()
    parts.push(hex_byte(b))
  }
  parts.join(":")
}

///|
/// Two lowercase hex digits for a byte value 0..255.
fn hex_byte(b : Int) -> String {
  let digits = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
  ]
  "\{digits[(b >> 4) & 0xF]}\{digits[b & 0xF]}"
}

///|
/// Render any SNMP value the way a CLI would. This is the one function
/// a caller usually wants: it picks the right rendering for the type,
/// and falls back to `Repr` for anything without a special form.
pub fn format_value(value : @ber.BerValue) -> String {
  match value {
    @ber.BerValue::OctetString(b) =>
      // A printable string prints as one; anything else is likely a
      // byte string (a MAC, an opaque key) and prints as hex.
      if !is_printable(b) {
        "Hex-STRING: \{hex_string(b)}"
      } else {
        let text = @utf8.decode_lossy(b)
        "\"\{text}\""
      }
    @ber.BerValue::ObjectIdentifier(o) => "OID: \{o.to_dotted()}"
    @ber.BerValue::Integer(n) => n.to_string()
    @ber.BerValue::Counter32(n) => format_counter32(n)
    @ber.BerValue::Gauge32(n) => format_gauge32(n)
    @ber.BerValue::TimeTicks(n) => format_time_ticks_full(n)
    @ber.BerValue::Counter64(n) => "Counter64(\{n})"
    @ber.BerValue::IpAddress(b) => format_ip_address(b)
    @ber.BerValue::Opaque(b) => "Opaque: \{hex_string(b)}"
    @ber.BerValue::Null => "NULL"
    @ber.BerValue::Sequence(_) => "<sequence>"
    @ber.BerValue::Tagged(tag, _) =>
      match tag {
        0x80 => "No Such Object available on this agent at this OID"
        0x81 => "No Such Instance currently exists at this OID"
        0x82 => "No more variables left in this MIB View"
        _ => "<tagged \{tag}>"
      }
  }
}

///|
/// Whether a byte string is safe to print as text: every byte is
/// printable ASCII or a tab/newline. Anything else is shown as hex, so
/// a binary value never lands as mojibake in a log.
fn is_printable(bytes : Bytes) -> Bool {
  if bytes.length() == 0 {
    return true
  }
  for i in 0..<bytes.length() {
    let b = bytes.at(i).to_uint().reinterpret_as_int()
    let ok = (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D
    if !ok {
      return false
    }
  }
  true
}

///|
/// Lowercase hex, no separators.
fn hex_string(bytes : Bytes) -> String {
  let out : Array[String] = []
  for i in 0..<bytes.length() {
    out.push(hex_byte(bytes.at(i).to_uint().reinterpret_as_int()))
  }
  out.join("")
}
