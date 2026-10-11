///|
/// Non-JavaScript stand-in for `exit_now`.
///
/// These programs need a socket, so they only run on the JavaScript
/// backend; this keeps the package compiling elsewhere so that
/// `moon check` covers it.
fn exit_now(code : Int) -> Unit {
  abort("these examples need the JavaScript target (exit \{code})")
}
