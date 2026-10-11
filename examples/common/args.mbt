///|
/// The little that the examples need in common: reading a target off the
/// command line, and lining text up in a column.
///
/// This is here rather than in each example so that an example shows how
/// to use the library and not how to parse argv. It is deliberately not
/// part of the library itself: parsing arguments is not the job of an
/// SNMP implementation.

///|
/// Where a program should talk to, and how.
pub struct Target {
  host : String
  port : Int
  /// The community to claim, as bytes: it is a byte string on the wire
  /// and not required to be text.
  community : Bytes
}

///|
/// Positional arguments, so an example can be run bare against a local
/// agent and pointed elsewhere when needed.
pub struct Cli {
  items : Array[String]
}

///|
/// Read the process arguments.
pub fn Cli::read() -> Cli {
  { items: @env.args(), }
}

///|
/// The argument at `index`, or `fallback` when absent or empty.
pub fn Cli::text(self : Cli, index : Int, fallback : String) -> String {
  match self.items.get(index) {
    Some(s) => if s == "" { fallback } else { s }
    None => fallback
  }
}

///|
/// A numeric argument, or `fallback` when absent or not a number.
pub fn Cli::number(self : Cli, index : Int, fallback : Int) -> Int {
  match parse_decimal(self.text(index, "")) {
    Some(n) => n
    None => fallback
  }
}

///|
/// `host`, `community` and an optional port — the order everyone types
/// them in, and the defaults a lab device usually has.
pub fn Cli::target(self : Cli) -> Target {
  {
    host: self.text(2, "127.0.0.1"),
    port: self.number(4, 161),
    community: @utf8.encode(self.text(3, "public")),
  }
}

///|
/// A decimal integer parser.
///
/// MoonBit core has no string-to-int this version could rely on, and a
/// port number is the only number these programs read.
pub fn parse_decimal(text : String) -> Int? {
  if text.length() == 0 {
    return None
  }
  let mut value = 0
  for c in text {
    let code = c.to_uint().reinterpret_as_int()
    if code < 0x30 || code > 0x39 {
      return None
    }
    value = value * 10 + (code - 0x30)
  }
  Some(value)
}

///|
/// Stop with an exit status, after the reason has been printed.
pub fn fail(code : Int) -> Unit {
  exit_now(code)
}

///|
/// Pad to `width` so values line up in a column.
pub fn pad(text : String, width : Int) -> String {
  let mut out = text
  while out.length() < width {
    out = out + " "
  }
  out
}

///|
/// Pad on the left, for numbers that should line up on the right.
pub fn pad_left(text : String, width : Int) -> String {
  let mut out = ""
  let mut n = text.length()
  while n < width {
    out = out + " "
    n = n + 1
  }
  out + text
}
