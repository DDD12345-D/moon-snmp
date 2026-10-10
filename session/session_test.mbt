///|
/// Blackbox tests for the session layer.
///
/// These never touch a socket: a scripted fake transport replays canned
/// datagrams (or raises a canned error) so request-id allocation, reply
/// matching, retry accounting and timeout surfacing can all be pinned
/// down deterministically.

///|
/// What the fake transport should do for one `recv` call.
enum Script {
  /// Hand back this datagram.
  Reply(Bytes)
  /// Fail the way a real socket does when nothing arrives.
  Timeout
  /// Fail the way a real socket does when the send syscall errors.
  /// The session treats any non-timeout failure as `NoResponse`.
  SendFailure
}

///|
/// A transport that replays a fixed script and records what was sent.
struct FakeTransport {
  script : Array[Script]
  mut cursor : Int
  sent : Array[Bytes]
  sent_hosts : Array[String]
  sent_ports : Array[Int]
}

///|
fn FakeTransport::new(script : Array[Script]) -> FakeTransport {
  { script, cursor: 0, sent: [], sent_hosts: [], sent_ports: [], }
}

///|
impl @session.Transport for FakeTransport with fn send(
  self : FakeTransport,
  host : String,
  port : Int,
  payload : Bytes,
) -> Unit raise @transport.TransportError {
  self.sent.push(payload)
  self.sent_hosts.push(host)
  self.sent_ports.push(port)
  match self.script.get(self.cursor) {
    Some(SendFailure) => {
      self.cursor = self.cursor + 1
      raise @transport.TransportError::SendFailed("scripted send failure")
    }
    _ => ()
  }
}

///|
impl @session.Transport for FakeTransport with fn recv(
  self : FakeTransport,
  _timeout_ms : Int,
) -> @transport.Datagram raise @transport.TransportError {
  match self.script.get(self.cursor) {
    None => raise @transport.TransportError::Timeout
    Some(step) => {
      self.cursor = self.cursor + 1
      match step {
        Reply(data) =>
          @transport.Datagram::{ from_addr: "127.0.0.1", from_port: 161, data, }
        Timeout | SendFailure => raise @transport.TransportError::Timeout
      }
    }
  }
}
