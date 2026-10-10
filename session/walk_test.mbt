///|
/// Blackbox tests for `walk` / `walk_bulk`.
///
/// These use an *agent-simulating* transport rather than a fixed byte
/// script: it decodes each request, looks it up in a table of
/// (oid, value) rows, and answers the way a real agent would for
/// GetRequest / GetNextRequest / GetBulkRequest. That way the walk
/// logic is exercised against replies produced by the same rules a real
/// agent uses, instead of against bytes that happen to line up.

///|
/// A tiny in-memory MIB: rows kept sorted by OID, as an agent holds
/// them. `next_calls` and `bulk_calls` let a test assert how many round
/// trips a walk actually made.
struct FakeAgent {
  rows : Array[@session.WalkEntry]
  mut next_calls : Int
  mut bulk_calls : Int
  /// The request the session sent, waiting to be answered by `recv`.
  mut pending : Bytes?
}

///|
fn FakeAgent::new(rows : Array[@session.WalkEntry]) -> FakeAgent {
  { rows, next_calls: 0, bulk_calls: 0, pending: None, }
}

///|
/// The row with exactly this OID, if any.
fn FakeAgent::exact(self : FakeAgent, target : @oid.Oid) -> @session.WalkEntry? {
  for row in self.rows {
    if row.name.compare(target) == 0 {
      return Some(row)
    }
  }
  None
}

///|
/// The first row strictly greater than `target`, which is what GETNEXT
/// returns. `None` means the agent would answer endOfMibView.
fn FakeAgent::successor(
  self : FakeAgent,
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
/// The v2c exception values, as an agent puts them on the wire.
fn end_of_mib_view() -> @ber.BerValue {
  @ber.BerValue::Tagged(0x82, [])
}

///|
fn no_such_object() -> @ber.BerValue {
  @ber.BerValue::Tagged(0x80, [])
}

///|
/// Turn one request into the var-binds an agent would return.
fn FakeAgent::answer(self : FakeAgent, pdu : @pdu.Pdu) -> Array[@pdu.VarBind] {
  match pdu {
    @pdu.Generic(p) =>
      match p.pdu_type {
        @pdu.GetRequest =>
          match p.varbinds.get(0) {
            None => []
            Some(vb) =>
              match self.exact(vb.name) {
                Some(row) => [@pdu.VarBind::new(row.name, row.value)]
                None => [@pdu.VarBind::new(vb.name, no_such_object())]
              }
          }
        @pdu.GetNextRequest => {
          self.next_calls = self.next_calls + 1
          match p.varbinds.get(0) {
            None => []
            Some(vb) =>
              match self.successor(vb.name) {
                Some(row) => [@pdu.VarBind::new(row.name, row.value)]
                None => [@pdu.VarBind::new(vb.name, end_of_mib_view())]
              }
          }
        }
        _ => []
      }
    @pdu.Bulk(p) => {
      self.bulk_calls = self.bulk_calls + 1
      let out : Array[@pdu.VarBind] = []
      // One repeating varbind: emit up to max_repetitions successors.
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
      out
    }
    @pdu.TrapV1(_) => []
  }
}

///|
impl @session.Transport for FakeAgent with fn send(
  self : FakeAgent,
  _host : String,
  _port : Int,
  payload : Bytes,
) -> Unit raise @transport.TransportError {
  self.pending = Some(payload)
}

///|
impl @session.Transport for FakeAgent with fn recv(
  self : FakeAgent,
  _timeout_ms : Int,
) -> @transport.Datagram raise @transport.TransportError {
  match self.pending {
    None => raise @transport.TransportError::Timeout
    Some(payload) => {
      self.pending = None
      let request = @pdu.Message::decode(payload) catch {
        _ => raise @transport.TransportError::Timeout
      }
      let varbinds = self.answer(request.pdu)
      let reply = @pdu.Message::new(
        request.version,
        request.community,
        @pdu.Pdu::response(request.pdu.request_id(), @pdu.NoError, 0, varbinds),
      )
      @transport.Datagram::{
        from_addr: "127.0.0.1",
        from_port: 161,
        data: reply.encode(),
      }
    }
  }
}

///|
/// A session driving a `FakeAgent`.
fn session_of(agent : FakeAgent) -> @session.Session[FakeAgent] {
  @session.Session::new(
    agent,
    "127.0.0.1",
    16161,
    @pdu.V2c,
    b"public",
    50,
    0,
    1000,
  )
}

///|
/// An agent that answers *every* GETNEXT with the same row, no matter
/// what was asked. Real agents do not do this, but a walk must survive
/// one that does rather than loop forever.
struct StuckAgent {
  fixed : @oid.Oid
  value : @ber.BerValue
  mut pending : Bytes?
}

///|
fn StuckAgent::new(fixed : @oid.Oid) -> StuckAgent {
  { fixed, value: @ber.BerValue::OctetString(b"stuck"), pending: None, }
}

///|
impl @session.Transport for StuckAgent with fn send(
  self : StuckAgent,
  _host : String,
  _port : Int,
  payload : Bytes,
) -> Unit raise @transport.TransportError {
  self.pending = Some(payload)
}

///|
impl @session.Transport for StuckAgent with fn recv(
  self : StuckAgent,
  _timeout_ms : Int,
) -> @transport.Datagram raise @transport.TransportError {
  match self.pending {
    None => raise @transport.TransportError::Timeout
    Some(payload) => {
      self.pending = None
      let request = @pdu.Message::decode(payload) catch {
        _ => raise @transport.TransportError::Timeout
      }
      // Always name the same OID, even for a GetRequest.
      let varbinds = [@pdu.VarBind::new(self.fixed, self.value)]
      let reply = @pdu.Message::new(
        request.version,
        request.community,
        @pdu.Pdu::response(request.pdu.request_id(), @pdu.NoError, 0, varbinds),
      )
      @transport.Datagram::{
        from_addr: "127.0.0.1",
        from_port: 161,
        data: reply.encode(),
      }
    }
  }
}

///|
/// Build a row for the table. OIDs are given comma-separated for
/// readability, the same convention the session tests use.
fn row(dotted : String, value : @ber.BerValue) -> @session.WalkEntry {
  @session.WalkEntry::{ name: oid(dotted), value, }
}

///|
/// The system group of a plausible agent, in agent order.
fn system_group() -> Array[@session.WalkEntry] {
  [
    row(
      "1, 3, 6, 1, 2, 1, 1, 1, 0",
      @ber.BerValue::OctetString(b"Linux testbox"),
    ),
    row(
      "1, 3, 6, 1, 2, 1, 1, 2, 0",
      @ber.BerValue::ObjectIdentifier(oid("1, 3, 6, 1, 4, 1, 8072, 3, 2, 10")),
    ),
    row("1, 3, 6, 1, 2, 1, 1, 3, 0", @ber.BerValue::TimeTicks(1234)),
    row(
      "1, 3, 6, 1, 2, 1, 1, 4, 0",
      @ber.BerValue::OctetString(b"dev@example.com"),
    ),
    row("1, 3, 6, 1, 2, 1, 1, 5, 0", @ber.BerValue::OctetString(b"testbox")),
    row("1, 3, 6, 1, 2, 1, 1, 6, 0", @ber.BerValue::OctetString(b"Lab")),
    // Something outside the system group, so a walk has a boundary.
    row("1, 3, 6, 1, 2, 1, 2, 1, 0", @ber.BerValue::Integer(3)),
  ]
}

///|
/// A short tag for a value's kind, for compact assertions.
fn kind_of(value : @ber.BerValue) -> String {
  match value {
    @ber.BerValue::OctetString(_) => "string"
    @ber.BerValue::Integer(_) => "int"
    @ber.BerValue::TimeTicks(_) => "ticks"
    @ber.BerValue::ObjectIdentifier(_) => "oid"
    _ => "other"
  }
}

///|
/// Render a walk as `name=kind` lines, which is compact to assert.
fn walk_shape(entries : Array[@session.WalkEntry]) -> String {
  let parts : Array[String] = []
  for e in entries {
    let kind = kind_of(e.value)
    parts.push("\{e.name.to_dotted()}=\{kind}")
  }
  parts.join(", ")
}
