///|
/// A datagram transport bound to one local UDP socket.
///
/// The socket lives in a worker thread (see `bridge_js.mbt`) so that a
/// blocking `recv` can park the caller on `Atomics.wait` while the
/// event loop keeps delivering packets. Callers only see
/// open / send / recv / close, so a future native implementation can
/// back the same interface.
pub struct Transport {
  /// The port the OS chose, or the one requested.
  local_port : Int
}

///|
/// Open a UDP socket. `bind_port` of 0 asks the OS for an ephemeral
/// port, which is what a manager wants.
///
/// Waits up to `bind_timeout_ms` for the socket to bind, because node
/// binds asynchronously and the worker must be ready before the first
/// send.
pub fn Transport::open(
  bind_port : Int,
  bind_timeout_ms : Int,
) -> Transport raise TransportError {
  js_udp_open(bind_port)
  let port = js_udp_wait_bound(bind_timeout_ms)
  if port < 0 {
    raise TransportError::UnsupportedPlatform
  }
  if port == 0 {
    raise TransportError::NotOpen
  }
  { local_port: port, }
}

///|
/// The local port the socket is bound to.
pub fn Transport::local_port(self : Transport) -> Int {
  self.local_port
}

///|
/// Send one datagram. `host` may be a name or a dotted-decimal address.
pub fn Transport::send(
  self : Transport,
  host : String,
  port : Int,
  payload : Bytes,
) -> Unit raise TransportError {
  let _ = self
  let sent = js_udp_send(payload, host, port)
  if sent < 0 {
    raise TransportError::SendFailed("send returned \{sent}")
  }
}

///|
/// Wait for the next datagram, up to `timeout_ms` milliseconds. Raises
/// `TransportError::Timeout` if nothing arrives in time.
///
/// Datagrams from any source are returned; the session layer is what
/// decides whether a reply belongs to its request.
pub fn Transport::recv(
  self : Transport,
  timeout_ms : Int,
) -> Datagram raise TransportError {
  let _ = self
  let n = js_udp_recv(timeout_ms)
  if n < 0 {
    raise TransportError::NotOpen
  }
  if n == 0 {
    raise TransportError::Timeout
  }
  let data = js_udp_take()
  let from_port = js_udp_from_port()
  { from_addr: "", from_port, data, }
}

///|
/// Release the socket and stop the worker. Safe to call more than once.
pub fn Transport::close(self : Transport) -> Unit {
  let _ = self
  js_udp_close()
}
