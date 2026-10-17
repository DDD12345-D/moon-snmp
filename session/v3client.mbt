///|
/// The v3 client.
///
/// A v3 conversation starts with a question that is not about the device
/// at all. Before a client can authenticate anything it has to learn the
/// agent's engine id and its clock, because the key it authenticates with
/// is derived from the engine id and the authenticator is only accepted
/// if the clock is close enough. That is *engine discovery* (RFC 3414
/// §4), and the agent answers it with a Report naming the engine and
/// counting the discovery as an "unknown engine id" — which is not an
/// error, it is the protocol working.
///
/// So `discover` runs once per client and everything else uses what it
/// learned. It happens on the first request rather than in the
/// constructor, so building a client cannot fail on a network problem.

///|
/// A v1/v2c session talks to an agent with a community; a v3 client talks
/// to an *engine*, as a user, with a security level. Everything else —
/// the socket, the timeouts, the request ids — works the same way, which
/// is why this lives beside `Session` rather than in a world of its own.
pub struct V3Client[T] {
  transport : T
  host : String
  port : Int
  security : @snmpv3.Security
  msg_max_size : Int
  timeout_ms : Int
  retries : Int
  /// The auth/priv keys, once the engine id is known.
  mut keys : @snmpv3.Keys?
  /// The discovered engine, or the unknown engine before that.
  mut engine : @snmpv3.Engine
  /// This client's own engine, used when it acts as a notification
  /// originator. A trap is authoritative for the *sender's* engine, so
  /// sending one needs an identity and a clock of our own — not the
  /// agent's. Unknown until `set_local_engine` is called.
  mut local_engine : @snmpv3.Engine
  /// Keys localized to `local_engine`, cached because localization
  /// stretches a password to a megabyte.
  mut local_keys : @snmpv3.Keys?
  mut next_msg_id : Int
  mut next_request_id : Int
  /// The counter AES privacy needs a fresh value from for every message.
  mut next_salt : Int
}

///|
/// Build a client. Nothing is sent and no key is derived until the first
/// request, so this cannot fail on a network problem.
pub fn[T] V3Client::new(
  transport : T,
  host : String,
  port : Int,
  security : @snmpv3.Security,
  timeout_ms : Int,
  retries : Int,
) -> V3Client[T] {
  {
    transport,
    host,
    port,
    security,
    msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
    timeout_ms,
    retries,
    keys: None,
    engine: @snmpv3.Engine::unknown(),
    local_engine: @snmpv3.Engine::unknown(),
    local_keys: None,
    next_msg_id: 1,
    next_request_id: 1,
    next_salt: 1,
  }
}

///|
/// The engine the agent reported. Empty until discovery has run.
pub fn[T] V3Client::engine(self : V3Client[T]) -> @snmpv3.Engine {
  self.engine
}

///|
/// Where this client is pointed.
pub fn[T] V3Client::addr(self : V3Client[T]) -> String {
  "\{self.host}:\{self.port}"
}

///|
/// The next message id.
fn[T] V3Client::take_msg_id(self : V3Client[T]) -> Int {
  let id = self.next_msg_id
  self.next_msg_id = self.next_msg_id + 1
  id
}

///|
/// The next request id.
///
/// A v3 message carries two independent ids: the message id in the
/// header and the request id in the PDU. The request id is what says a
/// reply belongs to a request, and a client that leaves it at zero
/// cannot tell a late duplicate of the previous reply from the answer it
/// is waiting for — which, in a walk, looks like an agent that stopped
/// advancing and silently truncates the result.
fn[T] V3Client::take_request_id(self : V3Client[T]) -> Int {
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
/// The next privacy salt. RFC 3826 §3.1.2.1 only requires that it not
/// repeat under the same key and clock, and a counter is the usual way to
/// guarantee that; it is 64 bits wide so it will not wrap in practice.
fn[T] V3Client::take_salt(self : V3Client[T]) -> Bytes {
  let value = self.next_salt
  self.next_salt = self.next_salt + 1
  // Eight octets: a fixed zero high half and a counter in the low half.
  // RFC 3826 §3.1.2.1 only asks that the value never repeat under the
  // same key and clock, and a counter that starts at one per client
  // cannot repeat within a session.
  let out : Array[Byte] = []
  out.append(@snmpv3.big_endian(0, 4))
  out.append(@snmpv3.big_endian(value, 4))
  Bytes::from_array(out)
}

///|
/// Learn the agent's engine id and clock, and derive the keys from it.
///
/// The probe is an unauthenticated, unencrypted GetRequest with no
/// var-binds, marked reportable. An agent that has never heard from this
/// client answers with a Report: the engine id, its boots and time, and
/// the fact that it counted an unknown engine id.
pub fn[T : Transport] V3Client::discover(
  self : V3Client[T],
) -> Unit raise SnmpError {
  let probe : @snmpv3.V3Message = {
    msg_id: self.take_msg_id(),
    msg_max_size: self.msg_max_size,
    flags: { reportable: true, authenticated: false, encrypted: false, },
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine: @snmpv3.Engine::unknown(),
    user: b"",
    auth_params: b"",
    priv_params: b"",
    data: @snmpv3.Plain({
      context_engine_id: b"",
      context_name: b"",
      pdu: @pdu.Pdu::request(@pdu.GetRequest, self.take_request_id(), []),
    }),
  }
  let reply = self.exchange(probe.encode()) catch {
    @transport.TransportError::Timeout => raise SnmpError::NoResponse
    _ => raise SnmpError::NoResponse
  }
  let message = @snmpv3.V3Message::decode(reply) catch {
    e => raise SnmpError::Security(e)
  }
  // The engine id is what matters here. A report is the expected answer;
  // anything else that names an engine is taken too, because an agent
  // that answers the probe directly has told us the same thing.
  if message.engine.id.length() == 0 {
    raise SnmpError::Security(
      @snmpv3.V3Error::NotReady("the agent did not name an engine"),
    )
  }
  self.engine = message.engine
  let keys = self.security.localize(message.engine.id) catch {
    e => raise SnmpError::Security(e)
  }
  self.keys = Some(keys)
}

///|
/// Send bytes and wait for a datagram, retrying on timeout the way the
/// v1/v2c session does.
fn[T : Transport] V3Client::exchange(
  self : V3Client[T],
  payload : Bytes,
) -> Bytes raise @transport.TransportError {
  let mut attempt = 0
  let mut answer : Bytes? = None
  while answer is None && attempt <= self.retries {
    self.transport.send(self.host, self.port, payload)
    let reply = self.transport.recv(self.timeout_ms) catch {
      @transport.TransportError::Timeout => {
        attempt = attempt + 1
        continue
      }
      e => raise e
    }
    answer = Some(reply.data)
  }
  match answer {
    Some(data) => data
    None => raise @transport.TransportError::Timeout
  }
}

///|
/// Send one PDU and return the reply's var-binds.
///
/// Discovery runs first if it has not already, so a caller can simply ask
/// a question. A Report that the agent sends in reply is raised as
/// `SnmpError::Security` carrying the Report, because a Report is the
/// agent saying no in a way the caller has to see.
pub fn[T : Transport] V3Client::request(
  self : V3Client[T],
  pdu : @pdu.Pdu,
) -> Array[@pdu.VarBind] raise SnmpError {
  match self.keys {
    None => self.discover()
    Some(_) => ()
  }
  let keys = match self.keys {
    Some(k) => k
    None => raise SnmpError::Security(@snmpv3.V3Error::NotReady("no keys"))
  }
  let request_id = self.take_request_id()

  let message : @snmpv3.V3Message = {
    msg_id: self.take_msg_id(),
    msg_max_size: self.msg_max_size,
    flags: @snmpv3.MsgFlags::of(self.security.level),
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine: self.engine,
    user: self.security.user,
    auth_params: b"",
    priv_params: b"",
    data: @snmpv3.Plain({
      context_engine_id: self.engine.id,
      context_name: b"",
      pdu: with_request_id(pdu, request_id),
    }),
  }
  let wire = @snmpv3.seal(message, self.security, keys, self.take_salt()) catch {
    e => raise SnmpError::Security(e)
  }
  let reply = self.exchange(wire) catch {
    @transport.TransportError::Timeout => raise SnmpError::NoResponse
    _ => raise SnmpError::NoResponse
  }
  let opened = @snmpv3.open(reply, self.security, keys) catch {
    e => raise SnmpError::Security(e)
  }
  // A Report is the agent refusing for a security reason: a wrong digest,
  // an unknown user, a clock too far out. Raise it rather than returning
  // an empty answer that looks like "no such OID".
  match @snmpv3.report_error(opened) {
    Some(e) => raise SnmpError::Security(e)
    None => ()
  }
  match opened.data {
    @snmpv3.Plain(scoped) =>
      match scoped.pdu {
        @pdu.Generic(p) => {
          // A datagram that names another request is not an answer to
          // this one. Failing is safer than returning it: a stale
          // duplicate would otherwise be read as the next step of a
          // walk.
          if p.request_id != request_id {
            raise SnmpError::ResponseIdMismatch
          }
          if p.error_status != @pdu.NoError {
            raise SnmpError::AgentError(p.error_status, p.error_index)
          }
          p.varbinds
        }
        @pdu.Bulk(p) => {
          if p.request_id != request_id {
            raise SnmpError::ResponseIdMismatch
          }
          p.varbinds
        }
        @pdu.TrapV1(_) => raise SnmpError::ResponseIdMismatch
      }
    @snmpv3.Encrypted(_) =>
      raise SnmpError::Security(
        @snmpv3.V3Error::NotReady("the reply stayed encrypted"),
      )
  }
}

///|
/// GET one value.
pub fn[T : Transport] V3Client::get(
  self : V3Client[T],
  oid : @oid.Oid,
) -> @pdu.VarBind raise SnmpError {
  let varbinds = self.request(
    @pdu.Pdu::request(@pdu.GetRequest, 0, [
      @pdu.VarBind::new(oid, @ber.BerValue::Null),
    ]),
  )
  match varbinds.get(0) {
    Some(vb) => vb
    None => raise SnmpError::ResponseIdMismatch
  }
}

///|
/// GET several values in one round trip.
pub fn[T : Transport] V3Client::get_many(
  self : V3Client[T],
  oids : Array[@oid.Oid],
) -> Array[@pdu.VarBind] raise SnmpError {
  let varbinds : Array[@pdu.VarBind] = []
  for oid in oids {
    varbinds.push(@pdu.VarBind::new(oid, @ber.BerValue::Null))
  }
  self.request(@pdu.Pdu::request(@pdu.GetRequest, 0, varbinds))
}

///|
/// GETNEXT from one OID.
pub fn[T : Transport] V3Client::get_next(
  self : V3Client[T],
  oid : @oid.Oid,
) -> @pdu.VarBind raise SnmpError {
  let varbinds = self.request(
    @pdu.Pdu::request(@pdu.GetNextRequest, 0, [
      @pdu.VarBind::new(oid, @ber.BerValue::Null),
    ]),
  )
  match varbinds.get(0) {
    Some(vb) => vb
    None => raise SnmpError::ResponseIdMismatch
  }
}

///|
/// GETBULK, the v2c and v3 way to read a table in a few round trips.
pub fn[T : Transport] V3Client::get_bulk(
  self : V3Client[T],
  oids : Array[@oid.Oid],
  non_repeaters : Int,
  max_repetitions : Int,
) -> Array[@pdu.VarBind] raise SnmpError {
  let varbinds : Array[@pdu.VarBind] = []
  for oid in oids {
    varbinds.push(@pdu.VarBind::new(oid, @ber.BerValue::Null))
  }
  self.request(
    @pdu.Bulk({ request_id: 0, non_repeaters, max_repetitions, varbinds, }),
  )
}

///|
/// SET one value (RFC 3416 §4.2.5).
///
/// Whether the write is allowed is decided by the agent's access rules
/// for this user, not by a community string, so a read-only user answers
/// with `notWritable` / `noAccess` and that surfaces as `AgentError`
/// rather than as a silent success.
pub fn[T : Transport] V3Client::set(
  self : V3Client[T],
  oid : @oid.Oid,
  value : @ber.BerValue,
) -> Array[@pdu.VarBind] raise SnmpError {
  self.request(
    @pdu.Pdu::request(@pdu.SetRequest, 0, [@pdu.VarBind::new(oid, value)]),
  )
}

///|
/// The walk primitives of a v3 client. The walk itself is the same
/// protocol logic as the community session's; only the wire format
/// differs, which is why it lives in `walk.mbt` and is given the three
/// requests as functions.
fn[T : Transport] v3_walk_access(client : V3Client[T]) -> WalkAccess {
  {
    get: fn(oid) raise SnmpError { client.get(oid) },
    get_next: fn(oid) raise SnmpError { client.get_next(oid) },
    get_bulk: fn(oids, non_repeaters, max_repetitions) raise SnmpError {
      client.get_bulk(oids, non_repeaters, max_repetitions)
    },
  }
}

///|
/// Walk the subtree rooted at `root` with GETNEXT, in agent order, over
/// a v3 session. The boundaries and the stopping rules are the ones
/// `walk_with` documents.
pub fn[T : Transport] V3Client::walk(
  self : V3Client[T],
  root : @oid.Oid,
  max_steps : Int,
) -> Array[WalkEntry] raise SnmpError {
  walk_with(v3_walk_access(self), root, max_steps)
}

///|
/// Walk the subtree rooted at `root` with GETBULK, which needs fewer
/// round trips than `walk` on a large table. Unlike the community
/// session, v3 always has GETBULK: there is no v1 to fall back to.
pub fn[T : Transport] V3Client::walk_bulk(
  self : V3Client[T],
  root : @oid.Oid,
  max_repetitions : Int,
  max_steps : Int,
) -> Array[WalkEntry] raise SnmpError {
  walk_bulk_with(v3_walk_access(self), root, max_repetitions, max_steps)
}

///|
/// Say who this client is when it sends traps.
///
/// A v3 trap is authoritative for the *sender's* engine (RFC 3414 §2.4):
/// the engine id, boots and time in the message header describe us, not
/// the device the trap is about, and the receiver derives the user's key
/// from that id. So an originator needs its own engine and a clock that
/// only moves forward — a receiver records the clock and refuses a
/// message that goes backwards.
///
/// The engine is supplied rather than generated: a real sender keeps it
/// across restarts (which is what makes the receiver's replay window
/// mean anything), and a test wants to pin it.
pub fn[T] V3Client::set_local_engine(
  self : V3Client[T],
  engine : @snmpv3.Engine,
) -> Unit {
  self.local_engine = engine
  self.local_keys = None
}

///|
/// The keys for our own engine, localized once and then cached.
fn[T] V3Client::notification_keys(
  self : V3Client[T],
) -> (@snmpv3.Engine, @snmpv3.Keys) raise SnmpError {
  if self.local_engine.id.length() == 0 {
    raise SnmpError::Security(
      @snmpv3.V3Error::NotReady(
        "set a local engine before sending v3 notifications",
      ),
    )
  }
  let keys = match self.local_keys {
    Some(k) => k
    None => {
      let k = self.security.localize(self.local_engine.id) catch {
        e => raise SnmpError::Security(e)
      }
      self.local_keys = Some(k)
      k
    }
  }
  (self.local_engine, keys)
}

///|
/// Send a v3 trap: unacknowledged, and scoped to our own engine.
///
/// The var-binds are the v2c ones — `sysUpTime.0` and `snmpTrapOID.0`
/// first, then whatever the caller adds (RFC 3416 §4.2.6) — because a
/// v3 notification is the same PDU in a different envelope.
pub fn[T : Transport] V3Client::trap(
  self : V3Client[T],
  uptime : UInt,
  trap_oid : @oid.Oid,
  varbinds : Array[@pdu.VarBind],
) -> Unit raise SnmpError {
  let (engine, keys) = self.notification_keys()
  let message : @snmpv3.V3Message = {
    msg_id: self.take_msg_id(),
    msg_max_size: self.msg_max_size,
    // A trap is unconfirmed: nothing will answer it, and a reportable
    // bit would invite a Report from engines that have never heard of us.
    flags: notification_flags(self.security.level),
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine,
    user: self.security.user,
    auth_params: b"",
    priv_params: b"",
    data: @snmpv3.Plain({
      context_engine_id: engine.id,
      context_name: b"",
      pdu: @pdu.Pdu::request(
        @pdu.TrapV2,
        0,
        notification_head(uptime, trap_oid, varbinds),
      ),
    }),
  }
  let wire = @snmpv3.seal(message, self.security, keys, self.take_salt()) catch {
    e => raise SnmpError::Security(e)
  }
  self.transport.send(self.host, self.port, wire) catch {
    _ => raise SnmpError::NoResponse
  }
}

///|
/// Send a v3 inform and wait for the receiver's acknowledgement.
///
/// An inform is confirmed, so its authoritative engine is the
/// *receiver* (RFC 3414 §2.4), not us: discovery runs against it, the
/// keys are derived from its engine id, and the Response it returns is
/// verified like any other reply. An unreachable receiver therefore
/// surfaces as `NoResponse` after the configured retries, which is the
/// whole reason to use an inform instead of a trap.
pub fn[T : Transport] V3Client::inform(
  self : V3Client[T],
  uptime : UInt,
  trap_oid : @oid.Oid,
  varbinds : Array[@pdu.VarBind],
) -> Array[@pdu.VarBind] raise SnmpError {
  self.request(
    @pdu.Pdu::request(
      @pdu.InformRequest,
      0,
      notification_head(uptime, trap_oid, varbinds),
    ),
  )
}
