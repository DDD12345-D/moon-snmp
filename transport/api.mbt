///|
/// A datagram transport bound to one local UDP socket.
///
/// The socket lives in a worker thread (see `bridge_js.mbt`) so that a
/// blocking `recv` can park the caller on `Atomics.wait` while the
/// event loop keeps delivering packets. Callers only see
/// open / send / recv / close, so a future native implementation can
/// back the same interface.
///
/// Each `Transport` owns its own socket, so a process can hold several:
/// a client querying an agent needs one, and a receiver listening for
/// that agent's traps needs another.
pub struct Transport {
  /// The registry slot of this socket. Opaque to callers.
  handle : Int
  /// The port the OS chose, or the one requested.
  local_port : Int
}

///|
/// Open a UDP socket. `bind_port` of 0 asks the OS for an ephemeral
/// port, which is what a client wants; a trap receiver passes the port
/// it should listen on.
///
/// Waits up to `bind_timeout_ms` for the socket to bind, because node
/// binds asynchronously and the worker must be ready before the first
/// send. Binding the same port twice raises `NotOpen` rather than
/// silently sharing, so a receiver can tell that its port is taken.
pub fn Transport::open(
  bind_port : Int,
  bind_timeout_ms : Int,
) -> Transport raise TransportError {
  js_udp_registry()
  let handle = js_udp_open(bind_port)
  if handle < 0 {
    raise TransportError::UnsupportedPlatform
  }
  let port = js_udp_wait_bound(handle, bind_timeout_ms)
  if port < 0 {
    // The socket reported an error, most often EADDRINUSE. Close it so
    // the worker does not linger.
    js_udp_close(handle)
    raise TransportError::NotOpen
  }
  if port == 0 {
    js_udp_close(handle)
    raise TransportError::Timeout
  }
  { handle, local_port: port, }
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
  let sent = js_udp_send(self.handle, payload, host, port)
  if sent < 0 {
    raise TransportError::SendFailed("send returned \{sent}")
  }
}

///|
/// Wait for the next datagram, up to `timeout_ms` milliseconds. Raises
/// `TransportError::Timeout` if nothing arrives in time.
///
/// Datagrams from any source are returned; the session layer is what
/// decides whether a reply belongs to its request, and a receiver is
/// what decides whether a notification is acceptable.
pub fn Transport::recv(
  self : Transport,
  timeout_ms : Int,
) -> Datagram raise TransportError {
  let n = js_udp_recv(self.handle, timeout_ms)
  if n < 0 {
    raise TransportError::NotOpen
  }
  if n == 0 {
    raise TransportError::Timeout
  }
  // Read the origin before `take` frees the slot, so the address and
  // the payload are guaranteed to describe the same datagram.
  let from_addr = js_udp_from_addr(self.handle)
  let from_port = js_udp_from_port(self.handle)
  let data = js_udp_take(self.handle)
  { from_addr, from_port, data, }
}

///|
/// How many datagrams this socket has dropped: ones larger than the
/// receive buffer, and ones that arrived with the queue already full.
///
/// A receiver should check this the way it checks its protocol-level
/// reject counter. Both failure modes look like silence otherwise, and
/// "I am losing traps" is exactly the thing a monitoring library must
/// not hide.
pub fn Transport::dropped_datagrams(self : Transport) -> Int {
  js_udp_dropped(self.handle)
}

///|
/// Release the socket and stop its worker. Safe to call more than once.
pub fn Transport::close(self : Transport) -> Unit {
  js_udp_close(self.handle)
}
