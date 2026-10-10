///|
/// The receiving end of a notification: a manager listening for traps
/// and informs.
///
/// A receiver is deliberately not a session. A session has one
/// destination and asks questions; a receiver has no destination at all
/// and is told things by whoever feels like it. What they share is the
/// transport, which is why `Receiver` takes the same `Transport` trait
/// the session does — the real socket, or a scripted stand-in in tests.

///|
/// A manager listening for notifications on one UDP socket.
pub struct Receiver[T] {
  transport : T
  /// The community to accept, or `None` to accept any. A receiver that
  /// cares is the norm (RFC 1157 §4.1 has a bad community dropped), but
  /// a lab receiver often wants to see everything that arrives.
  community : Bytes?
  /// Counters, so a caller can tell "nothing arrived" from "traffic
  /// arrived and was discarded". A receiver must never die because a
  /// stranger sent it something unparseable, so the drops are silent by
  /// design and visible only here.
  mut accepted : Int
  mut rejected : Int
  /// Informs that arrived but could not be acknowledged, because the
  /// sender's address was not reported by the transport.
  mut unacknowledged : Int
}

///|
/// Build a receiver. `community` of `None` accepts any community.
pub fn[T] Receiver::new(transport : T, community : Bytes?) -> Receiver[T] {
  { transport, community, accepted: 0, rejected: 0, unacknowledged: 0, }
}

///|
/// How many notifications were handed to the caller.
pub fn[T] Receiver::accepted(self : Receiver[T]) -> Int {
  self.accepted
}

///|
/// How many datagrams were discarded: unparseable, wrong community, or
/// not a notification at all.
pub fn[T] Receiver::rejected(self : Receiver[T]) -> Int {
  self.rejected
}

///|
/// How many informs arrived that could not be acknowledged.
pub fn[T] Receiver::unacknowledged(self : Receiver[T]) -> Int {
  self.unacknowledged
}

///|
/// Whether a community is acceptable. A receiver with no configured
/// community takes anything.
fn[T] Receiver::community_ok(self : Receiver[T], community : Bytes) -> Bool {
  match self.community {
    None => true
    Some(expected) => expected == community
  }
}

///|
/// Answer an inform with the Response RFC 3416 §4.2.6 requires: the
/// same request-id, the same community, error-status 0, and the same
/// var-binds echoed back. Sending it to the datagram's origin rather
/// than to a configured address is what lets one receiver serve many
/// senders.
fn[T : Transport] Receiver::acknowledge(
  self : Receiver[T],
  dg : @transport.Datagram,
  version : @pdu.Version,
  community : Bytes,
  request_id : Int,
  varbinds : Array[@pdu.VarBind],
) -> Unit {
  if dg.from_addr == "" {
    // Nothing to address the reply to. The sender will retransmit, so
    // this is recoverable, but it needs to be visible.
    self.unacknowledged = self.unacknowledged + 1
    return
  }
  let response = @pdu.Message::new(
    version,
    community,
    @pdu.Pdu::response(request_id, @pdu.NoError, 0, varbinds),
  )
  self.transport.send(dg.from_addr, dg.from_port, response.encode()) catch {
    _ => self.unacknowledged = self.unacknowledged + 1
  }
}

///|
/// Decode one datagram into a notification, or `None` if it is not one
/// we can accept (counted in `rejected`). Informs are acknowledged as a
/// side effect of being accepted.
fn[T : Transport] Receiver::accept(
  self : Receiver[T],
  dg : @transport.Datagram,
) -> Notification? {
  let message = @pdu.Message::decode(dg.data) catch {
    _ => {
      self.rejected = self.rejected + 1
      return None
    }
  }
  if !self.community_ok(message.community) {
    self.rejected = self.rejected + 1
    return None
  }
  let kind = match message.pdu {
    @pdu.TrapV1(_) => Some(TrapV1)
    @pdu.Generic(p) =>
      match p.pdu_type {
        @pdu.TrapV2 => Some(TrapV2)
        @pdu.InformRequest => Some(Inform)
        // A Response or a request arriving here is not a notification.
        _ => None
      }
    @pdu.Bulk(_) => None
  }
  match kind {
    None => {
      self.rejected = self.rejected + 1
      None
    }
    Some(k) => {
      if k == Inform {
        match message.pdu {
          @pdu.Generic(p) =>
            self.acknowledge(
              dg,
              message.version,
              message.community,
              p.request_id,
              p.varbinds,
            )
          _ => ()
        }
      }
      self.accepted = self.accepted + 1
      Some({
        kind: k,
        source_addr: dg.from_addr,
        source_port: dg.from_port,
        version: message.version,
        community: message.community,
        pdu: message.pdu,
      })
    }
  }
}

///|
/// Wait for the next notification, up to `timeout_ms` milliseconds.
///
/// A datagram that is not an acceptable notification is discarded and
/// the wait continues, so a stray packet cannot stop the receiver. The
/// timeout applies to each read, so noise does not cut the wait short
/// either.
///
/// `TransportError::Timeout` surfaces as `SnmpError::NoResponse`, so a
/// caller can loop:
///
/// ```mbt nocheck
/// while true {
///   let n = receiver.recv(1000) catch { SnmpError::NoResponse => continue; e => raise e }
///   handle(n)
/// }
/// ```
pub fn[T : Transport] Receiver::recv(
  self : Receiver[T],
  timeout_ms : Int,
) -> Notification raise SnmpError {
  let mut result : Notification? = None
  while result is None {
    let dg = self.transport.recv(timeout_ms) catch {
      @transport.TransportError::Timeout => raise SnmpError::NoResponse
      _ => raise SnmpError::NoResponse
    }
    result = self.accept(dg)
  }
  match result {
    Some(notification) => notification
    None => abort("receiver: no result after a non-empty read")
  }
}
