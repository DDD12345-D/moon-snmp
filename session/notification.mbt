///|
/// Notifications: the direction of SNMP that goes agent -> manager.
///
/// A trap is fire-and-forget: the sender never learns whether it
/// arrived. An inform is the acknowledged form — the receiver must send
/// back a Response with the same request-id and the same var-binds, and
/// the sender retransmits until it gets one. That difference is the
/// whole reason inform exists, so the sender here treats them
/// differently: `trap_v2` / `trap_v1` send and return, `inform` waits
/// for the acknowledgement the way `get` waits for its answer.

///|
/// Which of the three notification shapes arrived.
pub(all) enum NotificationKind {
  /// A v1 trap (RFC 1157 §4.1.6). Unacknowledged, and its body carries
  /// enterprise / agent-addr / generic / specific rather than a trap
  /// OID, so the meaning needs translating to be useful.
  TrapV1
  /// A v2c trap (RFC 3416 §4.2.6). Unacknowledged.
  TrapV2
  /// A v2c inform: the receiver must answer it.
  Inform
} derive(Eq, @debug.Debug)

///|
pub extend NotificationKind with Eq::{not_equal, equal}

///|
pub extend NotificationKind with @debug.Debug::{to_repr}

///|
/// What a v3 notification says about its security context.
///
/// A v1/v2c notification is identified by a community, which is a
/// shared secret and says nothing about who sent it. A v3 one is
/// identified by a user and authenticated against an engine, so a
/// receiver that logs a notification should log these too.
pub(all) struct V3Notification {
  /// The message's authoritative engine: the sender for a trap, and
  /// this receiver for an inform (the sender discovered it first).
  engine_id : Bytes
  /// The context the notification belongs to. A sender may name a
  /// context other than the default, and a receiver that answers an
  /// inform has to answer in the same one.
  context_engine_id : Bytes
  context_name : Bytes
  /// The user the message was authenticated as.
  user : Bytes
  /// The protection the sender used.
  level : @snmpv3.SecurityLevel
} derive(Eq, @debug.Debug)

///|
pub extend V3Notification with Eq::{not_equal, equal}

///|
pub extend V3Notification with @debug.Debug::{to_repr}

///|
/// A notification as it arrived, with where it came from.
///
/// The raw `Pdu` is kept rather than flattened into fields, because the
/// v1 and v2c shapes genuinely differ: a v2c notification names itself
/// with a trap OID var-bind, a v1 one carries a numeric generic trap
/// plus an enterprise OID. Flattening would mean a struct half full of
/// optionals; `trap_oid()` and `trap_v1()` below do the translating
/// when a caller wants the uniform view.
pub(all) struct Notification {
  kind : NotificationKind
  /// The sender's address, as the transport reported it.
  source_addr : String
  /// The sender's port. Aimed at the source of an inform's
  /// acknowledgement.
  source_port : Int
  version : @pdu.Version
  /// The community, for v1 and v2c; empty for v3, which has none.
  community : Bytes
  pdu : @pdu.Pdu
  /// Who sent it, when it arrived over v3.
  v3 : V3Notification?
} derive(Eq, @debug.Debug)

///|
pub extend Notification with Eq::{not_equal, equal}

///|
pub extend Notification with @debug.Debug::{to_repr}

///|
/// The var-binds the notification carries.
pub fn Notification::varbinds(self : Notification) -> Array[@pdu.VarBind] {
  self.pdu.varbinds()
}

///|
/// The request id. A v1 trap has no such field and reports 0.
pub fn Notification::request_id(self : Notification) -> Int {
  self.pdu.request_id()
}

///|
/// The sender's own uptime, in hundredths of a second.
///
/// A v2c notification carries it in the mandatory sysUpTime.0 var-bind
/// (RFC 3416 §4.2.6). A v1 trap has no such var-bind — its uptime is
/// the `time-stamp` field of the trap body (RFC 1157 §4.1.6) — so a v1
/// trap reports that instead, which is what makes this accessor uniform
/// across the three kinds.
///
/// `None` when the sender provided neither, which hand-rolled senders
/// sometimes do.
pub fn Notification::uptime(self : Notification) -> UInt? {
  match self.pdu {
    @pdu.TrapV1(t) => Some(t.time_stamp)
    _ => {
      for vb in self.pdu.varbinds() {
        if vb.name.compare(@mib.sys_up_time()) == 0 {
          match vb.value {
            @ber.BerValue::TimeTicks(n) => return Some(n)
            _ => ()
          }
        }
      }
      None
    }
  }
}

///|
/// What the notification is about, as one OID.
///
/// For a v2c trap or inform this is the snmpTrapOID.0 var-bind. For a
/// v1 trap it is derived: the standard generic traps map to their
/// well-known OIDs, and a vendor-specific one (generic 6) becomes
/// `enterprise.0.specific`, which is the v1-to-v2c translation
/// RFC 2576 §3.1 prescribes. `None` when the notification names nothing
/// at all.
pub fn Notification::trap_oid(self : Notification) -> @oid.Oid? {
  match self.pdu {
    @pdu.TrapV1(t) =>
      match @mib.v1_generic_trap_oid(t.generic_trap) {
        Some(o) => Some(o)
        None =>
          // enterprise.0.specific, the enterprise-specific trap form.
          if t.generic_trap == 6 {
            let parts = t.enterprise.parts()
            parts.push(0U)
            parts.push(t.specific_trap.reinterpret_as_uint())
            Some(@oid.Oid::from_parts(parts)) catch {
              _ => None
            }
          } else {
            None
          }
      }
    _ => {
      for vb in self.pdu.varbinds() {
        if vb.name.compare(@mib.snmp_trap_oid()) == 0 {
          match vb.value {
            @ber.BerValue::ObjectIdentifier(o) => return Some(o)
            _ => ()
          }
        }
      }
      None
    }
  }
}

///|
/// The v1 trap body, when this is a v1 trap.
pub fn Notification::trap_v1(self : Notification) -> @pdu.TrapV1Pdu? {
  match self.pdu {
    @pdu.TrapV1(t) => Some(t)
    _ => None
  }
}

///|
/// Build the two mandatory leading var-binds of a v2c notification
/// (RFC 3416 §4.2.6): sysUpTime.0, then snmpTrapOID.0.
fn notification_head(
  uptime : UInt,
  trap_oid : @oid.Oid,
  varbinds : Array[@pdu.VarBind],
) -> Array[@pdu.VarBind] {
  let out : Array[@pdu.VarBind] = [
    @pdu.VarBind::new(@mib.sys_up_time(), @ber.BerValue::TimeTicks(uptime)),
    @pdu.VarBind::new(
      @mib.snmp_trap_oid(),
      @ber.BerValue::ObjectIdentifier(trap_oid),
    ),
  ]
  for vb in varbinds {
    out.push(vb)
  }
  out
}

///|
/// The flags a notification or its acknowledgement carries: protected
/// like the session, but never reportable. Trap and Response are
/// unconfirmed PDUs (RFC 3412 §6.4); the reportable bit belongs to the
/// confirmed class, and `request` sets it on the way out.
fn notification_flags(level : @snmpv3.SecurityLevel) -> @snmpv3.MsgFlags {
  {
    reportable: false,
    authenticated: level != @snmpv3.NoAuthNoPriv,
    encrypted: level == @snmpv3.AuthPriv,
  }
}

///|
/// Send a PDU without waiting for an answer, which is what a trap
/// needs. The request id is still allocated and put on the wire: it
/// lets a receiver correlate a trap with anything else it logged, and
/// costs nothing to include.
///
/// `version` is passed explicitly rather than taken from the session: a
/// v1 trap is only valid in a v1 message and a v2c trap only in a v2c
/// one, so the notification kind decides.
fn[T : Transport] Session::send_only(
  self : Session[T],
  version : @pdu.Version,
  pdu : @pdu.Pdu,
) -> Unit raise SnmpError {
  let message = @pdu.Message::new(
    version,
    self.community,
    with_request_id(pdu, self.take_request_id()),
  )
  self.transport.send(self.host, self.port, message.encode()) catch {
    _ => raise SnmpError::NoResponse
  }
}

///|
/// Send a v2c trap (RFC 3416 §4.2.6). Unacknowledged: this returns as
/// soon as the datagram is handed to the OS, so `NoResponse` here means
/// the send itself failed, not that nobody listened.
///
/// `uptime` is the uptime of the entity the trap is about — put
/// `@mib.sys_up_time()` in a session as the agent and you would read it
/// there. `varbinds` are appended after the two mandatory ones.
pub fn[T : Transport] Session::trap_v2(
  self : Session[T],
  uptime : UInt,
  trap_oid : @oid.Oid,
  varbinds : Array[@pdu.VarBind],
) -> Unit raise SnmpError {
  self.send_only(
    @pdu.V2c,
    @pdu.Pdu::request(
      @pdu.TrapV2,
      0,
      notification_head(uptime, trap_oid, varbinds),
    ),
  )
}

///|
/// Send a v1 trap (RFC 1157 §4.1.6). Unacknowledged.
///
/// The message goes out as version 0 even if the session is set to
/// v2c: a v1 trap body inside a v2c message is not a valid combination,
/// and a lenient receiver would log it under the wrong version.
///
/// `generic_trap` is 0..6: 0 coldStart, 1 warmStart, 2 linkDown,
/// 3 linkUp, 4 authenticationFailure, 5 egpNeighborLoss, 6
/// enterprise-specific (where `specific_trap` carries the enterprise's
/// own code). `agent_addr` is the four-octet IPv4 address of the entity
/// the trap is about.
pub fn[T : Transport] Session::trap_v1(
  self : Session[T],
  enterprise : @oid.Oid,
  agent_addr : Bytes,
  generic_trap : Int,
  specific_trap : Int,
  uptime : UInt,
  varbinds : Array[@pdu.VarBind],
) -> Unit raise SnmpError {
  self.send_only(
    @pdu.V1,
    @pdu.Pdu::TrapV1({
      enterprise,
      agent_addr,
      generic_trap,
      specific_trap,
      time_stamp: uptime,
      varbinds,
    }),
  )
}

///|
/// Send a v2c inform and wait for the receiver's acknowledgement
/// (RFC 3416 §4.2.6).
///
/// An inform does not exist in v1, so the message goes out as v2c even
/// if the session is set to v1.
///
/// The retry policy is the session's, so an unreachable receiver
/// surfaces as `NoResponse` after the configured attempts, which is the
/// point of using an inform rather than a trap.
pub fn[T : Transport] Session::inform(
  self : Session[T],
  uptime : UInt,
  trap_oid : @oid.Oid,
  varbinds : Array[@pdu.VarBind],
) -> Array[@pdu.VarBind] raise SnmpError {
  self.request_versioned(
    @pdu.V2c,
    @pdu.Pdu::request(
      @pdu.InformRequest,
      0,
      notification_head(uptime, trap_oid, varbinds),
    ),
  )
}
