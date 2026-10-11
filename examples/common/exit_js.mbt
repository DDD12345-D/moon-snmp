///|
/// Stop the process with an exit status.
extern "js" fn exit_now(code : Int) -> Unit =
  #| function(code) {
  #|  process.exit(code);
  #| }
