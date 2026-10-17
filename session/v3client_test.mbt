///|
/// A v3 agent small enough to reason about, for testing the client
/// without a socket.
///
/// It speaks the real message format — the request is decoded with
/// `V3Message::decode` — but it uses `noAuthNoPriv`, so the tests
/// exercise the PDU-level behaviour of the client (which request it
/// sends, which reply it accepts) without also re-testing USM, which
/// `snmpv3/usm_test.mbt` covers against RFC vectors.
///
/// Writes are refused unless `writable` is set, which is how a
/// read-only user answers: an error-status in a Response, not silence.
struct FakeV3Agent {
  engine_id : Bytes
  rows : Array[@session.WalkEntry]
  mut writable : Bool
  mut wrong_id : Bool
  mut pending : Bytes?
  mut sets : Int
  mut informs : Int
  mut next_calls : Int
  mut bulk_calls : Int
}

///|
fn FakeV3Agent::new(rows : Array[@session.WalkEntry]) -> FakeV3Agent {
  {
    engine_id: b"\x80\x00\x1f\x88\x04test",
    rows,
    writable: false,
    wrong_id: false,
    pending: None,
    sets: 0,
    informs: 0,
    next_calls: 0,
    bulk_calls: 0,
  }
}

///|
/// The row with exactly this OID, if any.
fn FakeV3Agent::exact(
  self : FakeV3Agent,
  target : @oid.Oid,
) -> @session.WalkEntry? {
  for row in self.rows {
    if row.name.compare(target) == 0 {
      return Some(row)
    }
  }
  None
}

///|
/// The first row strictly greater than `target`.
fn FakeV3Agent::successor(
  self : FakeV3Agent,
  target : @oid.Oid,
) -> @session.WalkEntry? {
  for row in self.rows {
    if row.name.compare(target) > 0 {
      return Some(row)
    }
  }
  None
}

///|
/// Replace a row's value, the way an agent commits a SET.
fn FakeV3Agent::write(
  self : FakeV3Agent,
  target : @oid.Oid,
  value : @ber.BerValue,
) -> Unit {
  let mut i = 0
  while i < self.rows.length() {
    if self.rows[i].name.compare(target) == 0 {
      self.rows[i] = @session.WalkEntry::{ name: self.rows[i].name, value, }
      return
    }
    i = i + 1
  }
}

///|
/// Turn one request into the Response an agent would send.
fn FakeV3Agent::answer(self : FakeV3Agent, pdu : @pdu.Pdu) -> @pdu.Pdu {
  match pdu {
    @pdu.Generic(p) =>
      match p.pdu_type {
        @pdu.GetRequest =>
          match p.varbinds.get(0) {
            None => @pdu.Pdu::response(p.request_id, @pdu.NoError, 0, [])
            Some(vb) =>
              match self.exact(vb.name) {
                Some(row) =>
                  @pdu.Pdu::response(p.request_id, @pdu.NoError, 0, [
                    @pdu.VarBind::new(row.name, row.value),
                  ])
                None =>
                  @pdu.Pdu::response(p.request_id, @pdu.NoError, 0, [
                    @pdu.VarBind::new(vb.name, no_such_object()),
                  ])
              }
          }
        @pdu.GetNextRequest => {
          self.next_calls = self.next_calls + 1
          match p.varbinds.get(0) {
            None => @pdu.Pdu::response(p.request_id, @pdu.NoError, 0, [])
            Some(vb) =>
              match self.successor(vb.name) {
                Some(row) =>
                  @pdu.Pdu::response(p.request_id, @pdu.NoError, 0, [
                    @pdu.VarBind::new(row.name, row.value),
                  ])
                None =>
                  @pdu.Pdu::response(p.request_id, @pdu.NoError, 0, [
                    @pdu.VarBind::new(vb.name, end_of_mib_view()),
                  ])
              }
          }
        }
        @pdu.InformRequest => {
          // An inform is acknowledged with a Response carrying the same
          // request-id and the same var-binds (RFC 3416 §4.2.6).
          self.informs = self.informs + 1
          @pdu.Pdu::response(p.request_id, @pdu.NoError, 0, p.varbinds)
        }
        @pdu.SetRequest => {
          self.sets = self.sets + 1
          match p.varbinds.get(0) {
            None => @pdu.Pdu::response(p.request_id, @pdu.NoError, 0, [])
            Some(vb) =>
              if self.writable {
                self.write(vb.name, vb.value)
                @pdu.Pdu::response(p.request_id, @pdu.NoError, 0, [vb])
              } else {
                @pdu.Pdu::response(p.request_id, @pdu.NotWritable, 1, [vb])
              }
          }
        }
        _ => @pdu.Pdu::response(p.request_id, @pdu.GenErr, 0, [])
      }
    @pdu.Bulk(p) => {
      self.bulk_calls = self.bulk_calls + 1
      let out : Array[@pdu.VarBind] = []
      match p.varbinds.get(0) {
        None => ()
        Some(vb) => {
          let mut cursor = vb.name
          let mut n = 0
          while n < p.max_repetitions {
            match self.successor(cursor) {
              None => {
                out.push(@pdu.VarBind::new(cursor, end_of_mib_view()))
                break
              }
              Some(row) => {
                out.push(@pdu.VarBind::new(row.name, row.value))
                cursor = row.name
                n = n + 1
              }
            }
          }
        }
      }
      @pdu.Pdu::response(p.request_id, @pdu.NoError, 0, out)
    }
    @pdu.TrapV1(_) => @pdu.Pdu::response(0, @pdu.GenErr, 0, [])
  }
}

///|
/// The answer, renumbered to another request id when a test asks for a
/// reply that belongs to a different request.
fn FakeV3Agent::pdu_of(self : FakeV3Agent, request : @pdu.Pdu) -> @pdu.Pdu {
  let answer = self.answer(request)
  if !self.wrong_id {
    return answer
  }
  let id = request.request_id() + 1
  match answer {
    @pdu.Generic(p) =>
      @pdu.Pdu::response(id, p.error_status, p.error_index, p.varbinds)
    @pdu.Bulk(p) => @pdu.Pdu::response(id, @pdu.NoError, 0, p.varbinds)
    @pdu.TrapV1(t) => @pdu.Pdu::TrapV1(t)
  }
}

///|
impl @session.Transport for FakeV3Agent with fn send(
  self : FakeV3Agent,
  _host : String,
  _port : Int,
  payload : Bytes,
) -> Unit raise @transport.TransportError {
  self.pending = Some(payload)
}

///|
impl @session.Transport for FakeV3Agent with fn recv(
  self : FakeV3Agent,
  _timeout_ms : Int,
) -> @transport.Datagram raise @transport.TransportError {
  match self.pending {
    None => raise @transport.TransportError::Timeout
    Some(payload) => {
      self.pending = None
      let request = @snmpv3.V3Message::decode(payload) catch {
        _ => raise @transport.TransportError::Timeout
      }
      let scoped = match request.data {
        @snmpv3.Plain(scoped) => scoped
        @snmpv3.Encrypted(_) => raise @transport.TransportError::Timeout
      }
      let reply : @snmpv3.V3Message = {
        msg_id: request.msg_id,
        msg_max_size: request.msg_max_size,
        flags: { reportable: false, authenticated: false, encrypted: false, },
        security_model: request.security_model,
        engine: { id: self.engine_id, boots: 1, time: 100, },
        user: request.user,
        auth_params: b"",
        priv_params: b"",
        data: @snmpv3.Plain({
          context_engine_id: self.engine_id,
          context_name: b"",
          pdu: self.pdu_of(scoped.pdu),
        }),
      }
      @transport.Datagram::{
        from_addr: "127.0.0.1",
        from_port: 161,
        data: reply.encode(),
      }
    }
  }
}

///|
/// A v3 client driving a `FakeV3Agent`, with no authentication: what the
/// client asks for is what the agent sees, which is what these tests are
/// about.
fn v3_client_of(agent : FakeV3Agent) -> @session.V3Client[FakeV3Agent] {
  let security : @snmpv3.Security = {
    level: @snmpv3.NoAuthNoPriv,
    user: b"tester",
    auth_protocol: @snmpv3.None,
    auth_password: b"",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
  @session.V3Client::new(agent, "127.0.0.1", 16161, security, 50, 0)
}
