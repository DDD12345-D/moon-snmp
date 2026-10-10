///|
/// Errors the client layer can report.
///
/// `derive(Debug)` so a caller can put one in a log line. The variant
/// names are the stable part; the payloads are whatever the lower layer
/// reported.
pub suberror SnmpError {
  /// Every attempt timed out. The agent is down, unreachable, or (for a
  /// bad community in v1/v2c) deliberately silent per RFC 1157 §4.1.
  NoResponse
  /// A reply arrived but its request-id did not match any outstanding
  /// request, so it was discarded.
  ResponseIdMismatch
  /// The agent answered with a non-zero error-status (and the 0-based
  /// index of the var-bind it blames, or -1 when not applicable).
  AgentError(@pdu.ErrorStatus, Int)
  /// A BER or PDU level failure while decoding the reply.
  Malformed(@pdu.PduError)
} derive(@debug.Debug)

///|
pub extend SnmpError with @debug.Debug::{to_repr}

///|
/// The synchronous transport a session drives. `Transport` implements
/// it; tests provide a scripted stand-in. Kept as a trait so the client
/// logic can be exercised without a socket.
///
/// `pub(open)` so a stand-in in another package (the session tests) can
/// implement it.
pub(open) trait Transport {
  fn send(Self, host : String, port : Int, payload : Bytes) -> Unit raise @transport.TransportError
  fn recv(Self, timeout_ms : Int) -> @transport.Datagram raise @transport.TransportError
}

///|
/// The real UDP transport satisfies the interface.
pub impl Transport for @transport.Transport with fn send(
  self,
  host,
  port,
  payload,
) {
  @transport.Transport::send(self, host, port, payload)
}

///|
pub impl Transport for @transport.Transport with fn recv(self, timeout_ms) {
  @transport.Transport::recv(self, timeout_ms)
}
