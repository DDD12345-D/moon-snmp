///|
/// A single variable binding: an OID plus its value (RFC 3416 §3).
///
/// A GetRequest carries the value slot as `Null`; a Response fills it in.
pub(all) struct VarBind {
  name : @oid.Oid
  value : @ber.BerValue
} derive(Eq, @debug.Debug)

///|
pub extend VarBind with Eq::{not_equal, equal}

///|
pub extend VarBind with @debug.Debug::{to_repr}

///|
/// Build a var-bind. The name is validated by `Oid` itself.
pub fn VarBind::new(name : @oid.Oid, value : @ber.BerValue) -> VarBind {
  { name, value, }
}

///|
/// The PDU type tagged byte at the head of every PDU (RFC 3416 §3).
/// These are context-class constructed tags: 0xA0 | tag number.
pub(all) enum PduType {
  /// 0xA0: manager asks for one or more named values.
  GetRequest
  /// 0xA1: manager asks for the next value after each supplied OID.
  GetNextRequest
  /// 0xA2: agent answers a request (or reports an error).
  Response
  /// 0xA3: manager writes one or more named values.
  SetRequest
  /// 0xA4: v1 trap, whose PDU shape is different (RFC 1157 §4.1.6).
  Trap
  /// 0xA5: manager asks for a whole table in one round trip.
  GetBulkRequest
  /// 0xA6: v2c inform, a trap the receiver must acknowledge.
  InformRequest
  /// 0xA7: v2c trap, the unacknowledged counterpart of InformRequest.
  TrapV2
  /// 0xA8: v3 report, used by the engine for security failures.
  Report
} derive(Eq, @debug.Debug)

///|
pub extend PduType with Eq::{not_equal, equal}

///|
pub extend PduType with @debug.Debug::{to_repr}

///|
/// The context-class tag byte that identifies a PDU on the wire.
pub fn PduType::tag(self : PduType) -> Int {
  match self {
    GetRequest => 0xA0
    GetNextRequest => 0xA1
    Response => 0xA2
    SetRequest => 0xA3
    Trap => 0xA4
    GetBulkRequest => 0xA5
    InformRequest => 0xA6
    TrapV2 => 0xA7
    Report => 0xA8
  }
}

///|
/// Parse a PDU type from its tag byte.
pub fn PduType::from_tag(tag : Int) -> PduType raise PduError {
  match tag {
    0xA0 => GetRequest
    0xA1 => GetNextRequest
    0xA2 => Response
    0xA3 => SetRequest
    0xA4 => Trap
    0xA5 => GetBulkRequest
    0xA6 => InformRequest
    0xA7 => TrapV2
    0xA8 => Report
    other => raise PduError::UnknownPduTag(other)
  }
}

///|
/// The `error-status` field of a Response (RFC 3416 §3). Agents report
/// failures here rather than by dropping the packet.
pub(all) enum ErrorStatus {
  NoError
  TooBig
  NoSuchName
  BadValue
  ReadOnly
  GenErr
  NoAccess
  WrongType
  WrongLength
  WrongEncoding
  WrongValue
  NoCreation
  InconsistentValue
  ResourceUnavailable
  CommitFailed
  UndoFailed
  AuthorizationError
  NotWritable
  InconsistentName
} derive(Eq, @debug.Debug)

///|
pub extend ErrorStatus with Eq::{not_equal, equal}

///|
pub extend ErrorStatus with @debug.Debug::{to_repr}

///|
/// The integer an error-status travels as. The v1 codes are 0..5 and
/// the v2c additions are 6..18 (RFC 3416 §3).
pub fn ErrorStatus::to_int(self : ErrorStatus) -> Int {
  match self {
    NoError => 0
    TooBig => 1
    NoSuchName => 2
    BadValue => 3
    ReadOnly => 4
    GenErr => 5
    NoAccess => 6
    WrongType => 7
    WrongLength => 8
    WrongEncoding => 9
    WrongValue => 10
    NoCreation => 11
    InconsistentValue => 12
    ResourceUnavailable => 13
    CommitFailed => 14
    UndoFailed => 15
    AuthorizationError => 16
    NotWritable => 17
    InconsistentName => 18
  }
}

///|
/// Parse an error-status integer, rejecting undefined codes so a broken
/// agent cannot silently look like success.
pub fn ErrorStatus::from_int(n : Int) -> ErrorStatus raise PduError {
  match n {
    0 => NoError
    1 => TooBig
    2 => NoSuchName
    3 => BadValue
    4 => ReadOnly
    5 => GenErr
    6 => NoAccess
    7 => WrongType
    8 => WrongLength
    9 => WrongEncoding
    10 => WrongValue
    11 => NoCreation
    12 => InconsistentValue
    13 => ResourceUnavailable
    14 => CommitFailed
    15 => UndoFailed
    16 => AuthorizationError
    17 => NotWritable
    18 => InconsistentName
    other => raise PduError::UnknownErrorStatus(other)
  }
}
