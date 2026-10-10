///|
/// A single PDU. RFC 1157 (v1) and RFC 3416 (v2c) share the request /
/// response shape; only the v1 Trap differs, so it gets its own variant.
pub(all) enum Pdu {
  /// GetRequest / GetNextRequest / SetRequest / Response / Inform /
  /// TrapV2 / Report, whose body is
  /// `{ request-id, error-status, error-index, varbinds }`.
  ///
  /// `error-status` and `error-index` are zero for requests; only a
  /// Response fills them in. Callers encode that convention with
  /// `Pdu::request` / `Pdu::response`.
  Generic(GenericPdu)
  /// GetBulkRequest, whose second and third integer fields are
  /// `non-repeaters` and `max-repetitions` rather than error status
  /// (RFC 3416 §4.2.3).
  Bulk(BulkPdu)
  /// The v1 trap, whose body is a fixed set of fields (RFC 1157 §4.1.6).
  TrapV1(TrapV1Pdu)
} derive(Eq, @debug.Debug)

///|
pub extend Pdu with Eq::{not_equal, equal}

///|
pub extend Pdu with @debug.Debug::{to_repr}

///|
/// The `{ request-id, error-status, error-index, varbinds }` body.
pub(all) struct GenericPdu {
  pdu_type : PduType
  request_id : Int
  error_status : ErrorStatus
  error_index : Int
  varbinds : Array[VarBind]
} derive(Eq, @debug.Debug)

///|
pub extend GenericPdu with Eq::{not_equal, equal}

///|
pub extend GenericPdu with @debug.Debug::{to_repr}

///|
/// The GetBulkRequest body: `{ request-id, non-repeaters,
/// max-repetitions, varbinds }` (RFC 3416 §4.2.3).
pub(all) struct BulkPdu {
  request_id : Int
  /// How many leading varbinds to return a single value for.
  non_repeaters : Int
  /// How many successor values to return per remaining varbind.
  max_repetitions : Int
  varbinds : Array[VarBind]
} derive(Eq, @debug.Debug)

///|
pub extend BulkPdu with Eq::{not_equal, equal}

///|
pub extend BulkPdu with @debug.Debug::{to_repr}

///|
/// The v1 trap body (RFC 1157 §4.1.6). Only `enterprise`, `agent_addr`,
/// `generic_trap`, `specific_trap` and `time_stamp` travel on the wire;
/// the varbinds are usually the OBJECTS list from the trap definition.
pub(all) struct TrapV1Pdu {
  enterprise : @oid.Oid
  /// The agent's own address, four octets.
  agent_addr : Bytes
  /// 0..6 are the standard traps, 6 means "look at specific_trap".
  generic_trap : Int
  specific_trap : Int
  time_stamp : UInt
  varbinds : Array[VarBind]
} derive(Eq, @debug.Debug)

///|
pub extend TrapV1Pdu with Eq::{not_equal, equal}

///|
pub extend TrapV1Pdu with @debug.Debug::{to_repr}

///|
/// Build a request PDU (Get / GetNext / Set / etc) with a zeroed error
/// pair. Callers cannot accidentally send a non-zero error status on a
/// request, which real agents would ignore anyway.
pub fn Pdu::request(
  pdu_type : PduType,
  request_id : Int,
  varbinds : Array[VarBind],
) -> Pdu {
  Generic({
    pdu_type,
    request_id,
    error_status: NoError,
    error_index: 0,
    varbinds,
  })
}

///|
/// Build a Response PDU carrying an explicit error status and index.
pub fn Pdu::response(
  request_id : Int,
  error_status : ErrorStatus,
  error_index : Int,
  varbinds : Array[VarBind],
) -> Pdu {
  Generic({
    pdu_type: Response,
    request_id,
    error_status,
    error_index,
    varbinds,
  })
}

///|
/// The PDU type, whichever shape the PDU has.
pub fn Pdu::pdu_type(self : Pdu) -> PduType {
  match self {
    Generic(p) => p.pdu_type
    Bulk(_) => GetBulkRequest
    TrapV1(_) => Trap
  }
}

///|
/// The request id, whichever shape the PDU has.
pub fn Pdu::request_id(self : Pdu) -> Int {
  match self {
    Generic(p) => p.request_id
    Bulk(p) => p.request_id
    TrapV1(_) => 0
  }
}

///|
/// The varbind list, whichever shape the PDU has.
pub fn Pdu::varbinds(self : Pdu) -> Array[VarBind] {
  match self {
    Generic(p) => p.varbinds
    Bulk(p) => p.varbinds
    TrapV1(p) => p.varbinds
  }
}

///|
/// A complete SNMP message: `SEQUENCE { version, community, PDU }`
/// (RFC 3416 §7). The v3 header is different and lives in `v3`.
pub(all) struct Message {
  version : Version
  /// The community string, carried on the wire as an OCTET STRING. v3
  /// messages carry an empty string here and put the security
  /// parameters in the v3 header instead.
  community : Bytes
  pdu : Pdu
} derive(Eq, @debug.Debug)

///|
pub extend Message with Eq::{not_equal, equal}

///|
pub extend Message with @debug.Debug::{to_repr}

///|
/// Build a message. The community is taken as bytes because it is not
/// guaranteed to be UTF-8.
pub fn Message::new(version : Version, community : Bytes, pdu : Pdu) -> Message {
  { version, community, pdu, }
}
