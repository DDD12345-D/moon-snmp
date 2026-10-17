///|
/// Milliseconds since the epoch, for the engine clocks.
///
/// `Int64` and not `Int`: a millisecond count since 1970 needs 41 bits,
/// and a 32-bit counter would wrap every 24 days — for a monitor that
/// runs longer than that, a wrapping clock looks like a peer that
/// restarted.
extern "js" fn system_now_ms() -> Int64 =
  #| function() { return BigInt(Date.now()); }
