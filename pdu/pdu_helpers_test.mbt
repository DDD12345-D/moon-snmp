///|
/// Shared helpers for the PDU blackbox tests.

///|
/// Render bytes as lowercase hex.
fn hex(bytes : Bytes) -> String {
  let digits = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
  ]
  let out : Array[String] = []
  for i in 0..<bytes.length() {
    let b = bytes.at(i).to_uint().reinterpret_as_int()
    out.push(digits[b >> 4])
    out.push(digits[b & 0xF])
  }
  out.join("")
}

///|
/// Parse a lowercase hex string into bytes.
fn unhex(hex_text : String) -> Bytes {
  let bytes = @utf8.encode(hex_text)
  let out : Array[Byte] = []
  let mut i = 0
  while i + 1 < bytes.length() {
    out.push(((nibble(bytes.at(i)) << 4) | nibble(bytes.at(i + 1))).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
fn nibble(c : Byte) -> Int {
  let n = c.to_uint().reinterpret_as_int()
  if n >= 0x30 && n <= 0x39 {
    n - 0x30
  } else if n >= 0x61 && n <= 0x66 {
    n - 0x61 + 10
  } else {
    0
  }
}

///|
/// A v2c GetRequest for sysDescr.0 with community "public". The on-wire
/// shape net-snmp sends: SEQUENCE { INTEGER 1, OCTET STRING "public",
/// [0] { request-id, 0, 0, { { oid, NULL } } } }.
fn sys_descr_get_request() -> Bytes {
  unhex(
    "302902010104067075626c6963a01c02044a4d5a5a020100020100300e300c06082b060102010101000500",
  )
}
