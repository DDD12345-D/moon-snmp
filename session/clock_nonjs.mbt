///|
/// No clock on the backends that have no transport either.
///
/// The engine clocks only matter to code that talks over a socket, and
/// only the JavaScript backend can do that today. Returning zero keeps
/// the protocol layers compiling: with no time passing, the window is
/// never exceeded, which is the right answer for a world where nothing
/// moves. Tests inject their own clock through `set_clock`.
fn system_now_ms() -> Int64 {
  0L
}
