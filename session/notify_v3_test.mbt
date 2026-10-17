///|
/// Fakes and builders for the v3 notification cases.
///
/// Notifications are checked at the wire level here: a trap or inform is
/// built the way a sender builds one, then either sealed and handed to a
/// receiver, or captured from a sender and opened with the receiver's
/// keys. That is the only way to test the parts that matter — which
/// engine the message is scoped to, and whether the signature checks out
/// against a key the receiver can actually derive.

///|
/// A transport that records what was sent and replays what was queued.
struct Outbox {
  out : Array[(String, Int, Bytes)]
  inbox : Array[@transport.Datagram]
  mut read : Int
}

///|
fn Outbox::new(inbox : Array[@transport.Datagram]) -> Outbox {
  { out: [], inbox, read: 0, }
}

///|
impl @session.Transport for Outbox with fn send(
  self : Outbox,
  host : String,
  port : Int,
  payload : Bytes,
) -> Unit raise @transport.TransportError {
  self.out.push((host, port, payload))
}

///|
impl @session.Transport for Outbox with fn recv(
  self : Outbox,
  _timeout_ms : Int,
) -> @transport.Datagram raise @transport.TransportError {
  if self.read >= self.inbox.length() {
    raise @transport.TransportError::Timeout
  }
  let dg = self.inbox[self.read]
  self.read = self.read + 1
  dg
}

///|
/// A user authenticated with HMAC-MD5-96 and encrypted with AES-128.
/// MD5 here only because a test localizes a key several times and the
/// hash is the expensive part; production examples use SHA-1.
fn v3_test_security(
  user : Bytes,
  auth_password : Bytes,
  priv_password : Bytes,
) -> @snmpv3.Security {
  {
    level: @snmpv3.AuthPriv,
    user,
    auth_protocol: @snmpv3.Md5,
    auth_password,
    priv_protocol: @snmpv3.Aes128,
    priv_password,
  }
}

///|
/// The engine a sender claims when it originates a trap.
fn sender_engine() -> @snmpv3.Engine {
  { id: b"\x80\x00\x1f\x88\x04sender", boots: 3, time: 42, }
}

///|
/// The engine a receiver claims when it is authoritative for an inform.
fn receiver_engine() -> @snmpv3.Engine {
  { id: b"\x80\x00\x1f\x88\x04recver", boots: 1, time: 7, }
}

///|
/// The two mandatory v2c/v3 notification var-binds (RFC 3416 §4.2.6),
/// plus whatever the caller adds.
fn v3_notification_varbinds(
  uptime : UInt,
  trap_oid : @oid.Oid,
  extra : Array[@pdu.VarBind],
) -> Array[@pdu.VarBind] {
  let out : Array[@pdu.VarBind] = [
    @pdu.VarBind::new(@mib.sys_up_time(), @ber.BerValue::TimeTicks(uptime)),
    @pdu.VarBind::new(
      @mib.snmp_trap_oid(),
      @ber.BerValue::ObjectIdentifier(trap_oid),
    ),
  ]
  for vb in extra {
    out.push(vb)
  }
  out
}

///|
/// A v3 trap, sealed the way a sender seals one: scoped to `engine`,
/// signed with a key localized to it.
fn v3_trap_wire(
  engine : @snmpv3.Engine,
  security : @snmpv3.Security,
  uptime : UInt,
  trap_oid : @oid.Oid,
  extra : Array[@pdu.VarBind],
) -> Bytes {
  let keys = security.localize(engine.id) catch {
    _ => abort("the test key did not localize")
  }
  let message : @snmpv3.V3Message = {
    msg_id: 21,
    msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
    flags: { reportable: false, authenticated: true, encrypted: true, },
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine,
    user: security.user,
    auth_params: b"",
    priv_params: b"",
    data: @snmpv3.Plain({
      context_engine_id: engine.id,
      context_name: b"",
      pdu: @pdu.Pdu::request(
        @pdu.TrapV2,
        0,
        v3_notification_varbinds(uptime, trap_oid, extra),
      ),
    }),
  }
  @snmpv3.seal(message, security, keys, b"\x00\x00\x00\x00\x00\x00\x00\x01") catch {
    _ => abort("the test message did not seal")
  }
}

///|
/// A v3 inform, sealed the way a sender seals one after discovery:
/// scoped to the *receiver's* engine.
fn v3_inform_wire(
  engine : @snmpv3.Engine,
  security : @snmpv3.Security,
  request_id : Int,
  uptime : UInt,
  trap_oid : @oid.Oid,
  extra : Array[@pdu.VarBind],
) -> Bytes {
  let keys = security.localize(engine.id) catch {
    _ => abort("the test key did not localize")
  }
  let message : @snmpv3.V3Message = {
    msg_id: 22,
    msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
    flags: { reportable: true, authenticated: true, encrypted: true, },
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine,
    user: security.user,
    auth_params: b"",
    priv_params: b"",
    data: @snmpv3.Plain({
      context_engine_id: engine.id,
      context_name: b"",
      pdu: @pdu.Pdu::request(
        @pdu.InformRequest,
        request_id,
        v3_notification_varbinds(uptime, trap_oid, extra),
      ),
    }),
  }
  @snmpv3.seal(message, security, keys, b"\x00\x00\x00\x00\x00\x00\x00\x02") catch {
    _ => abort("the test message did not seal")
  }
}

///|
/// A discovery probe: an empty engine, an empty user, and an empty
/// GetRequest marked reportable (RFC 3414 §4).
fn v3_discovery_wire(request_id : Int) -> Bytes {
  let probe : @snmpv3.V3Message = {
    msg_id: 33,
    msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
    flags: { reportable: true, authenticated: false, encrypted: false, },
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine: @snmpv3.Engine::unknown(),
    user: b"",
    auth_params: b"",
    priv_params: b"",
    data: @snmpv3.Plain({
      context_engine_id: b"",
      context_name: b"",
      pdu: @pdu.Pdu::request(@pdu.GetRequest, request_id, []),
    }),
  }
  probe.encode()
}

///|
/// One datagram from a known origin.
fn v3_datagram(wire : Bytes) -> @transport.Datagram {
  { from_addr: "192.0.2.9", from_port: 9162, data: wire, }
}
