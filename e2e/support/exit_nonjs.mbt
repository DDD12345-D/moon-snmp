///|
/// Non-JavaScript stand-in for `exit_now`.
///
/// The harnesses only ever run on the JavaScript target (they need a
/// socket), but this package still has to compile for the other targets
/// so that `moon check` covers the module. A panic is the honest
/// fallback: reaching this means someone tried to run a socket harness
/// on a backend that has no socket.
fn exit_now(code : Int) -> Unit {
  abort("e2e harness needs the JavaScript target (exit \{code})")
}
