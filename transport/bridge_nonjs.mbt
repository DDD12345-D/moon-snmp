///|
/// Non-JavaScript stubs for the UDP bridge.
///
/// The MoonBit core library has no UDP primitive and this machine has no
/// native C toolchain, so the only working backend today is JS
/// (`node:dgram`, see `bridge_js.mbt`). These stubs keep the package
/// compiling on wasm/native: calling a transport there raises a clear
/// panic instead of failing the build, which leaves `moon check` and
/// `moon test` usable for the protocol layers above.
///
/// `moon.pkg` routes this file to every target that is not `js`.

///|
fn[T] panic_unimplemented() -> T = "%panic"

///|
fn js_udp_open(bind_port : Int) -> Unit {
  let _ = bind_port
  panic_unimplemented()
}

///|
fn js_udp_wait_bound(ms : Int) -> Int {
  let _ = ms
  panic_unimplemented()
}

///|
fn js_udp_send(payload : Bytes, host : String, port : Int) -> Int {
  let _ = payload
  let _ = host
  let _ = port
  panic_unimplemented()
}

///|
fn js_udp_recv(ms : Int) -> Int {
  let _ = ms
  panic_unimplemented()
}

///|
fn js_udp_take() -> Bytes {
  panic_unimplemented()
}

///|
fn js_udp_from_port() -> Int {
  panic_unimplemented()
}

///|
fn js_udp_close() -> Unit {
  panic_unimplemented()
}
