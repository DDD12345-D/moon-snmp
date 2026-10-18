///|
/// No clock and no sleep on the backends that have no socket either.
///
/// The examples only run on the JavaScript target (`moon.pkg` routes this
/// file everywhere else), so these exist to keep the package compiling
/// rather than to be called.
fn js_now_ms() -> Int64 {
  0L
}

///|
fn js_sleep(ms : Int) -> Unit {
  let _ = ms
}

///|
pub fn now_ms() -> Int64 {
  js_now_ms()
}

///|
pub fn sleep_ms(ms : Int) -> Unit {
  js_sleep(ms)
}
