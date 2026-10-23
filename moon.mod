// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "DDD12345-D/moon-snmp"

version = "0.3.1"

readme = "README.mbt.md"

repository = "https://github.com/DDD12345-D/moon-snmp"

license = "Apache-2.0"

keywords = [ "snmp", "network-management", "protocol", "ber" ]

// Every layer but the transport compiles for any backend, but anything
// that opens a socket only works on JavaScript (see transport). Making
// that the default means `moon run examples/query` just works, instead
// of failing with a stub panic because the caller forgot a flag.

preferred_target = "js"

description = "Pure MoonBit SNMP protocol library: client and notification receiver (v1, v2c, v3)"

import {
  "moonbitstack/mooncrypt@0.3.1",
}
