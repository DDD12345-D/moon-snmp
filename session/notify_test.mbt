///|
/// Blackbox tests for notifications and the receiver.
///
/// The two halves are tested against each other where possible: what
/// `Session::trap_v2` puts on the wire is fed to `Receiver::recv`, so
/// the encoder and the decoder cannot drift apart without a test
/// noticing. Nothing here opens a socket, so these run on any target.

///|
/// One datagram a fake transport was asked to send.
struct SentDatagram {
  host : String
  port : Int
  data : Bytes
} derive(Eq, @debug.Debug)

///|
/// A transport that hands out scripted datagrams and records what was
/// sent, so a receiver's acknowledgement can be inspected.
struct Mailbox {
  inbox : Array[@transport.Datagram]
  mut cursor : Int
  sent : Array[SentDatagram]
}

///|
fn Mailbox::new(inbox : Array[@transport.Datagram]) -> Mailbox {
  { inbox, cursor: 0, sent: [], }
}

///|
fn Mailbox::empty() -> Mailbox {
  Mailbox::new([])
}

///|
impl @session.Transport for Mailbox with fn send(
  self : Mailbox,
  host : String,
  port : Int,
  payload : Bytes,
) -> Unit raise @transport.TransportError {
  self.sent.push({ host, port, data: payload, })
}

///|
impl @session.Transport for Mailbox with fn recv(
  self : Mailbox,
  _timeout_ms : Int,
) -> @transport.Datagram raise @transport.TransportError {
  match self.inbox.get(self.cursor) {
    None => raise @transport.TransportError::Timeout
    Some(dg) => {
      self.cursor = self.cursor + 1
      dg
    }
  }
}

///|
/// Wrap a message as the datagram that would carry it.
fn datagram_of(
  message : @pdu.Message,
  addr : String,
  port : Int,
) -> @transport.Datagram {
  { from_addr: addr, from_port: port, data: message.encode(), }
}

///|
/// A v2c trap carrying the two mandatory var-binds plus `extra`, sent
/// with the given community.
fn trap_v2_wire_from(
  community : Bytes,
  request_id : Int,
  uptime : UInt,
  trap_oid : @oid.Oid,
  extra : Array[@pdu.VarBind],
) -> @pdu.Message {
  let varbinds : Array[@pdu.VarBind] = [
    @pdu.VarBind::new(@mib.sys_up_time(), @ber.BerValue::TimeTicks(uptime)),
    @pdu.VarBind::new(
      @mib.snmp_trap_oid(),
      @ber.BerValue::ObjectIdentifier(trap_oid),
    ),
  ]
  for vb in extra {
    varbinds.push(vb)
  }
  @pdu.Message::new(
    @pdu.V2c,
    community,
    @pdu.Pdu::request(@pdu.TrapV2, request_id, varbinds),
  )
}

///|
/// The same, with the usual "public" community.
fn trap_v2_wire(
  request_id : Int,
  uptime : UInt,
  trap_oid : @oid.Oid,
  extra : Array[@pdu.VarBind],
) -> @pdu.Message {
  trap_v2_wire_from(b"public", request_id, uptime, trap_oid, extra)
}

///|
/// An ifIndex var-bind, the usual payload of a linkUp / linkDown trap.
fn if_index_varbind(index : UInt) -> @pdu.VarBind {
  @pdu.VarBind::new(
    @mib.if_descr(),
    @ber.BerValue::OctetString(@utf8.encode("if\{index}")),
  )
}

///|
/// A session whose transport is the given mailbox, so its outgoing
/// bytes can be picked up.
fn session_over(mailbox : Mailbox) -> @session.Session[Mailbox] {
  @session.Session::new(
    mailbox,
    "10.0.0.9",
    162,
    @pdu.V2c,
    b"public",
    10,
    0,
    700,
  )
}

///|
/// A receiver whose transport is the given mailbox.
fn receiver_over(
  mailbox : Mailbox,
  community : Bytes?,
) -> @session.Receiver[Mailbox] {
  @session.Receiver::new(mailbox, community)
}
