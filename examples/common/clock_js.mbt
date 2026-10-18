///|
/// Milliseconds since the epoch.
///
/// A sampler needs this to divide by the time that actually passed,
/// rather than by the time it asked for: a walk takes as long as the
/// device takes, and a rate computed from the requested interval would be
/// quietly wrong on a slow one.
extern "js" fn js_now_ms() -> Int64 =
  #| function() { return BigInt(Date.now()); }

///|
/// Block for `ms` milliseconds.
///
/// The main thread may park on `Atomics.wait` because every socket lives
/// in a worker; spinning for a sampling interval would burn a core for
/// nothing. This is the same primitive `Transport::recv` waits on.
extern "js" fn js_sleep(ms : Int) -> Unit =
  #| function(ms) {
  #|   const sab = new SharedArrayBuffer(4);
  #|   Atomics.wait(new Int32Array(sab), 0, 0, ms);
  #| }

///|
pub fn now_ms() -> Int64 {
  js_now_ms()
}

///|
pub fn sleep_ms(ms : Int) -> Unit {
  js_sleep(ms)
}
