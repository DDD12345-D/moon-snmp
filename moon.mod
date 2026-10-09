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

version = "0.1.0"

readme = "README.mbt.md"

repository = "https://github.com/DDD12345-D/moon-snmp"

license = "Apache-2.0"

keywords = [ "snmp", "network-management", "protocol", "ber" ]

preferred_target = "wasm"

description = "Pure MoonBit implementation of the SNMP protocol client (v1, v2c, v3)"
