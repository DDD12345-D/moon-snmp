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
/// How many senders a receiver remembers localized keys for. Each new
/// engine id costs a megabyte of hashing to localize, so a listener
/// that sees traps from a handful of devices must not redo that work
/// per message; the cap keeps a spoofed-engine flood from growing the
/// cache without bound.
const PEER_CACHE_SIZE : Int = 8

///|
/// What a receiver remembers about one engine: its keys, and its clock.
///
/// The clock is what makes a replay visible. Authentication alone is not
/// enough: a recorded message verifies perfectly, and only the engine
/// time says it is not from now (RFC 3414 §3.2). `boots` of -1 means
/// "never seen" — the first message from a sender is taken at its word,
/// which is how USM bootstraps a peer.
struct Peer {
  engine_id : Bytes
  keys : @snmpv3.Keys
  mut boots : Int
  mut time : Int
  mut seen_ms : Int64
}

///|
/// A manager listening for notifications on one UDP socket.
pub struct Receiver[T] {
  transport : T
  /// The community to accept, or `None` to accept any. A receiver that
  /// cares is the norm (RFC 1157 §4.1 has a bad community dropped), but
  /// a lab receiver often wants to see everything that arrives.
  community : Bytes?
  /// The user to accept v3 notifications as, when this receiver speaks
  /// v3 at all.
  v3_security : @snmpv3.Security?
  /// This receiver's own engine. For an inform it is the authoritative
  /// engine — the sender discovers it before it can send anything — so
  /// it is also the identity reports and acknowledgements come from.
  v3_engine : @snmpv3.Engine
  /// Localized keys and the last-seen clock, by engine id. A trap is
  /// authenticated against the *sender's* engine, so both depend on who
  /// is talking.
  mut peers : Array[Peer]
  /// Milliseconds, so the engine clocks can advance. Replaceable, so a
  /// test can move time instead of waiting for it.
  mut clock : () -> Int64
  /// When `v3_engine` was recorded.
  mut engine_seen_ms : Int64
  /// The privacy salt for acknowledgements, never repeated under one key.
  mut next_salt : Int
  /// Counters, so a caller can tell "nothing arrived" from "traffic
  /// arrived and was discarded". A receiver must never die because a
  /// stranger sent it something unparseable, so the drops are silent by
  /// design and visible only here.
  mut accepted : Int
  mut rejected : Int
  /// Informs that arrived but could not be acknowledged, because the
  /// sender's address was not reported by the transport, or because
  /// this receiver is not the engine the message is addressed to.
  mut unacknowledged : Int
  /// Discovery probes answered: senders that asked who we are before
  /// sending an inform.
  mut discoveries : Int
}

///|
/// Build a receiver for v1/v2c. `community` of `None` accepts any.
pub fn[T] Receiver::new(transport : T, community : Bytes?) -> Receiver[T] {
  {
    transport,
    community,
    v3_security: None,
    v3_engine: @snmpv3.Engine::unknown(),
    peers: [],
    clock: system_now_ms,
    engine_seen_ms: 0L,
    next_salt: 1,
    accepted: 0,
    rejected: 0,
    unacknowledged: 0,
    discoveries: 0,
  }
}

///|
/// Build a receiver that also speaks v3, as `security`, with `engine` as
/// its own identity.
///
/// `engine` is not decoration: an inform is addressed to the receiver's
/// engine, and the sender learns it by discovery. A receiver with an
/// empty engine id therefore cannot receive informs — it has nothing to
/// tell a sender. Traps do not need it (their authoritative engine is
/// the sender's), but they do need `security` to hold the right
/// password.
///
/// v1/v2c notifications are still accepted, since a device may be
/// configured to send either.
pub fn[T] Receiver::v3(
  transport : T,
  engine : @snmpv3.Engine,
  security : @snmpv3.Security,
) -> Receiver[T] {
  {
    transport,
    community: None,
    v3_security: Some(security),
    v3_engine: engine,
    peers: [],
    clock: system_now_ms,
    engine_seen_ms: system_now_ms(),
    next_salt: 1,
    accepted: 0,
    rejected: 0,
    unacknowledged: 0,
    discoveries: 0,
  }
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
/// How many v3 senders were told what this engine is.
pub fn[T] Receiver::discoveries(self : Receiver[T]) -> Int {
  self.discoveries
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
/// The next privacy salt. Unique per message under one key, which is all
/// RFC 3826 §3.1.2.1 asks.
fn[T] Receiver::take_salt(self : Receiver[T]) -> Bytes {
  let value = self.next_salt
  self.next_salt = self.next_salt + 1
  let out : Array[Byte] = []
  out.append(@snmpv3.big_endian(0, 4))
  out.append(@snmpv3.big_endian(value, 4))
  Bytes::from_array(out)
}

///|
/// The keys for one engine id, localized at most once per engine.
fn[T] Receiver::peer_index(
  self : Receiver[T],
  security : @snmpv3.Security,
  engine_id : Bytes,
) -> Int raise SnmpError {
  let mut i = 0
  while i < self.peers.length() {
    if self.peers[i].engine_id == engine_id {
      return i
    }
    i = i + 1
  }
  let keys = security.localize(engine_id) catch {
    e => raise SnmpError::Security(e)
  }
  if self.peers.length() >= PEER_CACHE_SIZE {
    // Simplest bound: start over rather than track ages. A receiver
    // talking to more than a handful of engines pays for it again.
    self.peers = []
  }
  self.peers.push({ engine_id, keys, boots: -1, time: 0, seen_ms: 0L, })
  self.peers.length() - 1
}

///|
/// One peer's clock as it stands now: what was last seen, advanced by the
/// time that has passed since.
fn[T] Receiver::peer_clock(
  self : Receiver[T],
  index : Int,
  now_ms : Int64,
) -> @snmpv3.Engine {
  let peer = self.peers[index]
  let reference : @snmpv3.Engine = {
    id: peer.engine_id,
    boots: peer.boots,
    time: peer.time,
  }
  reference.advanced(now_ms - peer.seen_ms)
}

///|
/// Take a message's clock as the peer's new reference.
///
/// A higher boots means the peer restarted, so the clock resets to what
/// it says; otherwise the reference moves forward and never back.
fn[T] Receiver::record(
  self : Receiver[T],
  index : Int,
  engine : @snmpv3.Engine,
  now_ms : Int64,
) -> Unit {
  let reference = self.peer_clock(index, now_ms)
  if self.peers[index].boots < 0 || engine.boots > reference.boots {
    self.peers[index].boots = engine.boots
    self.peers[index].time = engine.time
  } else if engine.time > reference.time {
    self.peers[index].time = engine.time
  } else {
    self.peers[index].time = reference.time
  }
  self.peers[index].seen_ms = now_ms
}

///|
/// Use another clock. Call it before the first message; a receiver cannot
/// re-date clocks it has already recorded.
pub fn[T] Receiver::set_clock(self : Receiver[T], clock : () -> Int64) -> Unit {
  self.clock = clock
  self.engine_seen_ms = clock()
}

///|
/// This receiver's own clock as it stands now: what `v3_engine` says,
/// advanced by the time that has passed since construction.
fn[T] Receiver::v3_engine_now(
  self : Receiver[T],
  now_ms : Int64,
) -> @snmpv3.Engine {
  self.v3_engine.advanced(now_ms - self.engine_seen_ms)
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
/// Tell a sender what this engine is, so it can address an inform to it.
///
/// Discovery is a message with an empty engine id and an empty user,
/// and the answer is a Report counting an unknown engine id — which is
/// the protocol working, not an error (RFC 3414 §4). The Report is
/// unauthenticated because there is nothing yet to authenticate with.
fn[T : Transport] Receiver::answer_discovery(
  self : Receiver[T],
  dg : @transport.Datagram,
  probe : @snmpv3.V3Message,
) -> Unit {
  if self.v3_engine.id.length() == 0 || dg.from_addr == "" {
    self.rejected = self.rejected + 1
    return
  }
  self.discoveries = self.discoveries + 1
  // The clock in a Report is what a sender records and compares later,
  // so it has to be the clock now, not the one from construction.
  let ours = self.v3_engine_now((self.clock)())
  let request_id = match probe.scoped() {
    Some(scoped) => scoped.pdu.request_id()
    None => 0
  }
  let report = @pdu.Pdu::request(@pdu.Report, request_id, [
    @pdu.VarBind::new(
      @snmpv3.usm_stats_unknown_engine_ids(),
      @ber.BerValue::Counter32(self.discoveries.reinterpret_as_uint()),
    ),
  ])
  let message : @snmpv3.V3Message = {
    msg_id: probe.msg_id,
    msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
    flags: { reportable: false, authenticated: false, encrypted: false, },
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine: ours,
    user: b"",
    auth_params: b"",
    priv_params: b"",
    data: @snmpv3.Plain({
      context_engine_id: ours.id,
      context_name: b"",
      pdu: report,
    }),
  }
  self.transport.send(dg.from_addr, dg.from_port, message.encode()) catch {
    _ => self.unacknowledged = self.unacknowledged + 1
  }
}

///|
/// Acknowledge a v3 inform. The reply is scoped to *our* engine and
/// signed with the same user's key, at the level the inform arrived
/// with: the sender derived its key from our engine id during discovery,
/// so this is the only form it can verify.
fn[T : Transport] Receiver::acknowledge_v3(
  self : Receiver[T],
  dg : @transport.Datagram,
  security : @snmpv3.Security,
  message : @snmpv3.V3Message,
  scoped : @snmpv3.ScopedPdu,
  request_id : Int,
  varbinds : Array[@pdu.VarBind],
) -> Unit {
  if dg.from_addr == "" {
    self.unacknowledged = self.unacknowledged + 1
    return
  }
  let now_ms = (self.clock)()
  let index = self.peer_index(security, self.v3_engine.id) catch {
    _ => {
      self.unacknowledged = self.unacknowledged + 1
      return
    }
  }
  let keys = self.peers[index].keys
  // The sender compares this clock against the one it discovered, and
  // will refuse an acknowledgement that is more than 150 seconds old —
  // which is what a fixed value becomes after two and a half minutes.
  let ours = self.v3_engine_now(now_ms)
  let response : @snmpv3.V3Message = {
    // A Response echoes the msgID of the message it answers (RFC 3412
    // §7.1.2). A sender may use it to match the reply to its request,
    // and net-snmp does: a fresh id here makes the acknowledgement
    // arrive and be discarded.
    msg_id: message.msg_id,
    msg_max_size: @snmpv3.DEFAULT_MAX_SIZE,
    flags: notification_flags(message.flags.level()),
    security_model: @snmpv3.USM_SECURITY_MODEL,
    engine: ours,
    user: message.user,
    auth_params: b"",
    priv_params: b"",
    // A Response stays in the context the request named. Echoing it
    // rather than substituting our own is what the sender compares
    // against.
    data: @snmpv3.Plain({
      context_engine_id: scoped.context_engine_id,
      context_name: scoped.context_name,
      pdu: @pdu.Pdu::response(request_id, @pdu.NoError, 0, varbinds),
    }),
  }
  let wire = @snmpv3.seal(response, security, keys, self.take_salt()) catch {
    _ => {
      self.unacknowledged = self.unacknowledged + 1
      return
    }
  }
  self.transport.send(dg.from_addr, dg.from_port, wire) catch {
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
    // Not a v1/v2c message. It may still be a v3 one: a v3 header is a
    // different shape, not a longer v2c one.
    _ => return self.accept_v3(dg)
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
        v3: None,
      })
    }
  }
}

///|
/// Decode a v3 datagram, if this receiver speaks v3 at all.
fn[T : Transport] Receiver::accept_v3(
  self : Receiver[T],
  dg : @transport.Datagram,
) -> Notification? {
  match self.v3_security {
    None => {
      self.rejected = self.rejected + 1
      None
    }
    Some(security) => self.accept_v3_with(dg, security)
  }
}

///|
/// What a v3 datagram means, once we know the user to check it against.
fn[T : Transport] Receiver::accept_v3_with(
  self : Receiver[T],
  dg : @transport.Datagram,
  security : @snmpv3.Security,
) -> Notification? {
  let message = @snmpv3.V3Message::decode(dg.data) catch {
    _ => {
      self.rejected = self.rejected + 1
      return None
    }
  }
  // Discovery: no engine id, empty user, nothing to authenticate. It is
  // not a notification, so it is neither accepted nor rejected.
  if message.engine.id.length() == 0 {
    self.answer_discovery(dg, message)
    return None
  }
  let now_ms = (self.clock)()
  let index = self.peer_index(security, message.engine.id) catch {
    _ => {
      self.rejected = self.rejected + 1
      return None
    }
  }
  let keys = self.peers[index].keys
  let opened = @snmpv3.open(dg.data, security, keys) catch {
    // A wrong password, an unknown user, or a message that was tampered
    // with. All three are "not for us" and must not stop the receiver.
    _ => {
      self.rejected = self.rejected + 1
      return None
    }
  }
  // Authentication says who sent it; the clock says when. A message that
  // replayed an old recording would verify perfectly, so the window is
  // the only thing that refuses it. The first message from an engine is
  // taken at its word, which is how USM bootstraps a sender.
  let verdict = if security.auth_protocol == @snmpv3.None {
    // Nothing was authenticated, so there is no clock to defend: USM's
    // window exists to keep an authenticator from being replayed.
    @snmpv3.Fresh
  } else if message.engine.id == self.v3_engine.id {
    @snmpv3.local_timeliness(message.engine, self.v3_engine_now(now_ms))
  } else if self.peers[index].boots < 0 {
    @snmpv3.Fresh
  } else {
    @snmpv3.peer_timeliness(message.engine, self.peer_clock(index, now_ms))
  }
  match verdict {
    @snmpv3.Stale => {
      self.rejected = self.rejected + 1
      return None
    }
    _ => ()
  }
  self.record(index, message.engine, now_ms)
  match opened.data {
    @snmpv3.Encrypted(_) => {
      self.rejected = self.rejected + 1
      None
    }
    @snmpv3.Plain(scoped) => self.accept_v3_pdu(dg, security, message, scoped)
  }
}

///|
/// Turn a verified v3 PDU into a notification, acknowledging an inform
/// when this receiver is the engine it was addressed to.
fn[T : Transport] Receiver::accept_v3_pdu(
  self : Receiver[T],
  dg : @transport.Datagram,
  security : @snmpv3.Security,
  message : @snmpv3.V3Message,
  scoped : @snmpv3.ScopedPdu,
) -> Notification? {
  let pdu = scoped.pdu
  let kind = match pdu {
    @pdu.Generic(p) =>
      match p.pdu_type {
        @pdu.TrapV2 => Some(TrapV2)
        @pdu.InformRequest => Some(Inform)
        _ => None
      }
    _ => None
  }
  match kind {
    None => {
      self.rejected = self.rejected + 1
      None
    }
    Some(k) => {
      if k == Inform {
        // Only the authoritative engine may answer an inform. For an
        // inform addressed to this receiver that is us; an inform
        // naming another engine cannot be acknowledged from here.
        if message.engine.id == self.v3_engine.id {
          match pdu {
            @pdu.Generic(p) =>
              self.acknowledge_v3(
                dg,
                security,
                message,
                scoped,
                p.request_id,
                p.varbinds,
              )
            _ => ()
          }
        } else {
          self.unacknowledged = self.unacknowledged + 1
        }
      }
      self.accepted = self.accepted + 1
      Some({
        kind: k,
        source_addr: dg.from_addr,
        source_port: dg.from_port,
        version: @pdu.V3,
        community: b"",
        pdu,
        v3: Some({
          engine_id: message.engine.id,
          context_engine_id: scoped.context_engine_id,
          context_name: scoped.context_name,
          user: message.user,
          level: message.flags.level(),
        }),
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
