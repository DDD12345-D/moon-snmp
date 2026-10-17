///|
/// "Is this device there?" as one call.
///
/// A monitoring loop can always ask a question and see whether it gets an
/// answer, but every caller then writes the same `catch { NoResponse =>
/// ... }` and the same "which OID is cheap and always present" decision.
/// This is that decision made once: `sysUpTime.0` is a scalar every agent
/// has to implement, it costs one round trip, and its value says how long
/// the device thinks it has been up.
///
/// What it cannot do is tell "down" from "configured wrong": in v1 and
/// v2c a wrong community is answered with silence (RFC 1157 §4.1), and in
/// v3 a wrong password is a security error, so those two land in
/// different places on purpose — see `probe` on the v3 client.

///|
/// What one probe found.
pub(all) struct Liveness {
  /// Whether the device answered at all.
  reachable : Bool
  /// `sysUpTime.0` in hundredths of a second, or 0 when it did not
  /// answer, or answered with something that is not a clock.
  uptime : UInt
} derive(Eq, @debug.Debug)

///|
pub extend Liveness with Eq::{not_equal, equal}

///|
pub extend Liveness with @debug.Debug::{to_repr}

///|
/// Read a var-bind as liveness. Anything that is not a TimeTicks still
/// means the device answered — an agent whose clock is broken is not the
/// same thing as an agent that is gone.
fn liveness_of(value : @ber.BerValue) -> Liveness {
  match value {
    @ber.BerValue::TimeTicks(n) => { reachable: true, uptime: n, }
    _ => { reachable: true, uptime: 0, }
  }
}

///|
/// Ask a v1/v2c agent whether it is there.
///
/// Silence is returned as `reachable: false` rather than raised, because
/// "no answer" is the normal answer from a device that is down — and, in
/// v1/v2c, from one whose community is wrong. Everything else (a
/// malformed reply, an agent error) is a real problem and is raised.
pub fn[T : Transport] Session::probe(
  self : Session[T],
) -> Liveness raise SnmpError {
  let vb = self.get(@mib.sys_up_time()) catch {
    SnmpError::NoResponse => return { reachable: false, uptime: 0, }
    e => raise e
  }
  liveness_of(vb.value)
}

///|
/// Ask a v3 agent whether it is there, as the configured user.
///
/// Same shape as the community session's, with one difference that
/// matters for an operator: a wrong password is a `Security` error, not
/// silence. That is deliberate — the device is reachable, and saying so
/// is more useful than reporting it as down.
pub fn[T : Transport] V3Client::probe(
  self : V3Client[T],
) -> Liveness raise SnmpError {
  let vb = self.get(@mib.sys_up_time()) catch {
    SnmpError::NoResponse => return { reachable: false, uptime: 0, }
    e => raise e
  }
  liveness_of(vb.value)
}
