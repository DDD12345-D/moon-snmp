///|
/// A client session bound to one agent address, one community and one
/// transport. Holds the request-id counter and the timing policy, so a
/// caller can issue many requests without repeating that setup.
pub struct Session[T] {
  transport : T
  host : String
  port : Int
  version : @pdu.Version
  community : Bytes
  /// Milliseconds to wait for a reply on each attempt.
  timeout_ms : Int
  /// Attempts after the first. 0 means send once and report a timeout.
  retries : Int
  /// The last request id handed out; the next one is this plus one, so
  /// ids differ between consecutive requests as RFC 3416 §4.1 asks.
  mut next_request_id : Int
}

///|
/// Build a session. `request_id_start` is where the id counter begins;
/// net-snmp starts at a random value, which is good practice because
/// some agents cache replies.
pub fn[T] Session::new(
  transport : T,
  host : String,
  port : Int,
  version : @pdu.Version,
  community : Bytes,
  timeout_ms : Int,
  retries : Int,
  request_id_start : Int,
) -> Session[T] {
  {
    transport,
    host,
    port,
    version,
    community,
    timeout_ms,
    retries,
    next_request_id: request_id_start,
  }
}

///|
/// The address this session talks to.
pub fn[T] Session::addr(self : Session[T]) -> String {
  "\{self.host}:\{self.port}"
}

///|
/// Hand out the next request id, wrapping instead of overflowing so a
/// long-lived session keeps working.
pub fn[T] Session::take_request_id(self : Session[T]) -> Int {
  let id = self.next_request_id
  // Stay inside the signed 32-bit range SNMP integers use.
  if id >= 2147483647 {
    self.next_request_id = 1
  } else {
    self.next_request_id = id + 1
  }
  id
}

///|
/// Return a copy of `pdu` carrying `request_id`. A v1 trap has no
/// request id field, so it passes through untouched (a session should
/// not be sending one anyway).
fn with_request_id(pdu : @pdu.Pdu, request_id : Int) -> @pdu.Pdu {
  match pdu {
    @pdu.Generic(p) => @pdu.Generic({ ..p, request_id, })
    @pdu.Bulk(p) => @pdu.Bulk({ ..p, request_id, })
    @pdu.TrapV1(_) => pdu
  }
}

///|
/// Send one PDU and return the reply's var-binds, retrying on timeout.
///
/// A v1/v2c agent drops a request whose community is wrong without
/// replying (RFC 1157 §4.1), so the only thing that comes back is a
/// timeout; after `retries` extra attempts this raises `NoResponse`.
pub fn[T : Transport] Session::request(
  self : Session[T],
  pdu : @pdu.Pdu,
) -> Array[@pdu.VarBind] raise SnmpError {
  self.request_versioned(self.version, pdu)
}

///|
/// The request loop, with an explicit version.
///
/// The version normally comes from the session, but a notification
/// pins its own: a v1 trap must travel in a v1 message (version 0) and
/// an inform only exists in v2c, no matter what the session is set to.
/// Sending either in the wrong version produces a message no receiver
/// should accept.
pub fn[T : Transport] Session::request_versioned(
  self : Session[T],
  version : @pdu.Version,
  pdu : @pdu.Pdu,
) -> Array[@pdu.VarBind] raise SnmpError {
  let request_id = self.take_request_id()
  // The caller builds the PDU with a placeholder id; the session is the
  // one that owns the counter, so it stamps the real id in here. This
  // keeps `Pdu::request` free of session state.
  let message = @pdu.Message::new(
    version,
    self.community,
    with_request_id(pdu, request_id),
  )
  let wire = message.encode()
  let mut attempt = 0
  let mut answer : Array[@pdu.VarBind]? = None
  while answer is None && attempt <= self.retries {
    self.transport.send(self.host, self.port, wire) catch {
      _ => raise SnmpError::NoResponse
    }
    // One attempt window. A datagram that belongs to somebody else is
    // discarded here and we keep reading; only a timeout ends the
    // window, and only a timeout costs a retry.
    let mut window_open = true
    while window_open && answer is None {
      let outcome : @transport.Datagram? = Some(
        self.transport.recv(self.timeout_ms),
      ) catch {
        @transport.TransportError::Timeout => None
        _ => raise SnmpError::NoResponse
      }
      match outcome {
        None => window_open = false
        Some(reply) => {
          let decoded = @pdu.Message::decode(reply.data) catch {
            e => raise SnmpError::Malformed(e)
          }
          if decoded.pdu.request_id() == request_id {
            // `return` is not allowed inside a match arm, so bind the
            // outcome and let the loop conditions end the search.
            answer = Some(
              match decoded.pdu {
                @pdu.Generic(p) => {
                  if p.error_status != @pdu.NoError {
                    raise SnmpError::AgentError(p.error_status, p.error_index)
                  }
                  p.varbinds
                }
                @pdu.Bulk(p) => p.varbinds
                @pdu.TrapV1(_) => raise SnmpError::ResponseIdMismatch
              },
            )
          }
        }
      }
    }
    if answer is None {
      attempt = attempt + 1
    }
  }
  match answer {
    Some(varbinds) => varbinds
    None => raise SnmpError::NoResponse
  }
}

///|
/// GET one value (RFC 3416 §4.2.1).
pub fn[T : Transport] Session::get(
  self : Session[T],
  oid : @oid.Oid,
) -> @pdu.VarBind raise SnmpError {
  let varbinds = self.request(
    @pdu.Pdu::request(@pdu.GetRequest, 0, [
      @pdu.VarBind::new(oid, @ber.BerValue::Null),
    ]),
  )
  match varbinds {
    [vb] => vb
    _ => raise SnmpError::ResponseIdMismatch
  }
}

///|
/// GET one value per OID in a single round trip.
pub fn[T : Transport] Session::get_many(
  self : Session[T],
  oids : Array[@oid.Oid],
) -> Array[@pdu.VarBind] raise SnmpError {
  let varbinds : Array[@pdu.VarBind] = []
  for oid in oids {
    varbinds.push(@pdu.VarBind::new(oid, @ber.BerValue::Null))
  }
  self.request(@pdu.Pdu::request(@pdu.GetRequest, 0, varbinds))
}

///|
/// GETNEXT: the lexicographically next OID after `oid` (RFC 3416
/// §4.2.2). This is the primitive `walk` is built from.
pub fn[T : Transport] Session::get_next(
  self : Session[T],
  oid : @oid.Oid,
) -> @pdu.VarBind raise SnmpError {
  let varbinds = self.request(
    @pdu.Pdu::request(@pdu.GetNextRequest, 0, [
      @pdu.VarBind::new(oid, @ber.BerValue::Null),
    ]),
  )
  match varbinds {
    [vb] => vb
    _ => raise SnmpError::ResponseIdMismatch
  }
}

///|
/// GETBULK: up to `max_repetitions` successors for each of the OIDs
/// after the first `non_repeaters` (RFC 3416 §4.2.3). v2c only.
pub fn[T : Transport] Session::get_bulk(
  self : Session[T],
  oids : Array[@oid.Oid],
  non_repeaters : Int,
  max_repetitions : Int,
) -> Array[@pdu.VarBind] raise SnmpError {
  let varbinds : Array[@pdu.VarBind] = []
  for oid in oids {
    varbinds.push(@pdu.VarBind::new(oid, @ber.BerValue::Null))
  }
  self.request(
    @pdu.Bulk({
      request_id: 0, // replaced by `request`
      non_repeaters,
      max_repetitions,
      varbinds,
    }),
  )
}

///|
/// SET one value (RFC 3416 §4.2.5). Read-only agents answer with
/// `notWritable` or `readOnly`, which surfaces as `AgentError`.
pub fn[T : Transport] Session::set(
  self : Session[T],
  oid : @oid.Oid,
  value : @ber.BerValue,
) -> Array[@pdu.VarBind] raise SnmpError {
  self.request(
    @pdu.Pdu::request(@pdu.SetRequest, 0, [@pdu.VarBind::new(oid, value)]),
  )
}
