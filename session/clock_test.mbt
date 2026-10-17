///|
/// A clock a test can move.
///
/// The behaviour worth testing — a message older than the 150-second
/// window being refused, and a sender whose clock keeps moving — takes
/// minutes of real time to reach otherwise, which means it would never
/// run in CI. Injecting the clock is the only way to test it at all.

///|
struct FakeClock {
  mut now : Int64
}

///|
fn FakeClock::new() -> FakeClock {
  { now: 1000000L, }
}

///|
fn FakeClock::advance(self : FakeClock, seconds : Int) -> Unit {
  self.now = self.now + seconds.to_int64() * 1000L
}

///|
fn FakeClock::read(self : FakeClock) -> Int64 {
  self.now
}

///|
/// The reader a client or receiver takes as its clock.
fn clock_of(clock : FakeClock) -> () -> Int64 {
  fn() { clock.read() }
}
