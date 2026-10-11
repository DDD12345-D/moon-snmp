///|
/// Stop the process with an exit status, so a failing harness reports
/// its status without the noise of a panic. CI reads the status; a
/// human reads the summary that was already printed.
extern "js" fn exit_now(code : Int) -> Unit =
  #| function(code) {
  #|  process.exit(code);
  #| }
