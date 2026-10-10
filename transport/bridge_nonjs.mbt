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
fn js_udp_registry() -> Unit {
  panic_unimplemented()
}

///|
fn js_udp_open(bind_port : Int) -> Int {
  let _ = bind_port
  panic_unimplemented()
}

///|
fn js_udp_wait_bound(handle : Int, ms : Int) -> Int {
  let _ = handle
  let _ = ms
  panic_unimplemented()
}

///|
fn js_udp_send(handle : Int, payload : Bytes, host : String, port : Int) -> Int {
  let _ = handle
  let _ = payload
  let _ = host
  let _ = port
  panic_unimplemented()
}

///|
fn js_udp_recv(handle : Int, ms : Int) -> Int {
  let _ = handle
  let _ = ms
  panic_unimplemented()
}

///|
fn js_udp_take(handle : Int) -> Bytes {
  let _ = handle
  panic_unimplemented()
}

///|
fn js_udp_from_port(handle : Int) -> Int {
  let _ = handle
  panic_unimplemented()
}

///|
fn js_udp_from_addr(handle : Int) -> String {
  let _ = handle
  panic_unimplemented()
}

///|
fn js_udp_close(handle : Int) -> Unit {
  let _ = handle
  panic_unimplemented()
}
