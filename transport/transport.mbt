///|
/// Errors a UDP transport can report.
pub(all) suberror TransportError {
  /// The transport has not been opened, or was already closed.
  NotOpen
  /// Sending failed (the socket reported an error).
  SendFailed(String)
  /// No datagram arrived before the deadline.
  Timeout
  /// The platform cannot provide UDP at all. On the non-JavaScript
  /// backends today this transport is a stub, because the MoonBit
  /// standard library has no UDP primitive and the native backend needs
  /// a C toolchain; the JS backend uses node:dgram.
  ///
  /// Host names need no separate error: `dgram.send` resolves them in
  /// node, so an unresolvable host surfaces as a send failure.
  UnsupportedPlatform
}

///|
/// What a receive returned.
pub(all) struct Datagram {
  /// The sender's address, as dotted decimal. The JS bridge does not
  /// currently report it, so this is empty; matching a reply to its
  /// request uses the port and the request id instead.
  from_addr : String
  /// The sender's port.
  from_port : Int
  /// The payload.
  data : Bytes
} derive(Eq, @debug.Debug)

///|
pub extend Datagram with Eq::{not_equal, equal}

///|
pub extend Datagram with @debug.Debug::{to_repr}
