///|
/// Helpers shared by the end-to-end harnesses in `e2e/`.
///
/// These exist so a harness reads as a list of checks rather than as
/// plumbing, and so a failure is reported with the label of the check
/// that produced it. The exit code is what CI reads, so a harness must
/// end non-zero when any check failed.

///|
/// A running tally of named checks.
pub struct Checks {
  mut passed : Int
  failures : Array[String]
}

///|
pub fn Checks::new() -> Checks {
  { passed: 0, failures: [], }
}

///|
/// Record a check that held.
pub fn Checks::ok(self : Checks, label : String) -> Unit {
  self.passed = self.passed + 1
  println("  ok   \{label}")
}

///|
/// Record a check that did not hold, with the detail that shows why.
pub fn Checks::bad(self : Checks, label : String, detail : String) -> Unit {
  self.failures.push("\{label}: \{detail}")
  println("  FAIL \{label}: \{detail}")
}

///|
/// Check a condition.
pub fn Checks::that(self : Checks, label : String, cond : Bool) -> Unit {
  if cond {
    self.ok(label)
  } else {
    self.bad(label, "condition was false")
  }
}

///|
/// Check that two pieces of text are equal.
pub fn Checks::text(
  self : Checks,
  label : String,
  got : String,
  want : String,
) -> Unit {
  if got == want {
    self.ok(label)
  } else {
    self.bad(label, "got \"\{got}\", wanted \"\{want}\"")
  }
}

///|
/// Check that two integers are equal.
pub fn Checks::num(
  self : Checks,
  label : String,
  got : Int,
  want : Int,
) -> Unit {
  if got == want {
    self.ok(label)
  } else {
    self.bad(label, "got \{got}, wanted \{want}")
  }
}

///|
/// Check that a value is at least `least`.
pub fn Checks::at_least(
  self : Checks,
  label : String,
  got : Int,
  least : Int,
) -> Unit {
  if got >= least {
    self.ok("\{label} (\{got})")
  } else {
    self.bad(label, "got \{got}, wanted at least \{least}")
  }
}

///|
/// How many checks failed.
pub fn Checks::failed(self : Checks) -> Int {
  self.failures.length()
}

///|
/// Print the summary and, if anything failed, stop with a non-zero exit
/// status — which is what makes a CI job red rather than merely
/// informative.
pub fn Checks::finish(self : Checks, suite : String) -> Unit {
  let failed = self.failed()
  println("")
  if failed == 0 {
    println("\{suite}: \{self.passed} checks passed")
    return
  }
  println("\{suite}: \{failed} of \{failed + self.passed} checks FAILED")
  for failure in self.failures {
    println("  - \{failure}")
  }
  exit_now(1)
}

///|
/// Stop the harness with an exit status, without a panic trace.
///
/// A harness uses this when it cannot even start — a missing argument,
/// an unknown mode — where the reason has already been printed.
pub fn exit_with(code : Int) -> Unit {
  exit_now(code)
}

///|
/// A decimal integer parser.
///
/// MoonBit core has no string-to-int this version could rely on, and a
/// harness only needs to read a port number, so this is the whole thing.
pub fn parse_decimal(text : String) -> Int? {
  if text.length() == 0 {
    return None
  }
  let mut value = 0
  for c in text {
    let code = c.to_uint().reinterpret_as_int()
    if code < 0x30 || code > 0x39 {
      return None
    }
    value = value * 10 + (code - 0x30)
  }
  Some(value)
}

///|
/// Positional arguments with defaults, so a harness can be run bare
/// against the standard docker setup and pointed elsewhere when needed.
pub struct Args {
  /// Everything after the program name.
  items : Array[String]
}

///|
pub fn Args::read() -> Args {
  { items: @env.args(), }
}

///|
/// The argument at `index`, or `fallback` when it is absent or empty.
pub fn Args::text(self : Args, index : Int, fallback : String) -> String {
  match self.items.get(index) {
    Some(s) => if s == "" { fallback } else { s }
    None => fallback
  }
}

///|
/// A numeric argument, or `fallback` when it is absent or not a number.
pub fn Args::number(self : Args, index : Int, fallback : Int) -> Int {
  match parse_decimal(self.text(index, "")) {
    Some(n) => n
    None => fallback
  }
}
