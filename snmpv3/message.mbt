///|
/// The SNMPv3 message format (RFC 3412 §6) and the User-based Security
/// Model that rides inside it (RFC 3414).
///
/// A v3 message is not a v1/v2c message with more fields. The version is
/// still there, but the community is replaced by a security model, the
/// PDU is wrapped in a *scoped* PDU naming the context it belongs to,
/// and the thing that identifies the sender is an engine id plus a user
/// name rather than a shared string. The layout is
///
///   SEQUENCE {
///     msgVersion            3,
///     msgGlobalData         SEQUENCE { msgID, msgMaxSize, msgFlags, msgSecurityModel },
///     msgSecurityParameters  OCTET STRING holding the USM parameters,
///     msgData                the scoped PDU, plaintext or encrypted
///   }
///
/// Three details are easy to get wrong and are handled here:
///
///   * `msgSecurityParameters` is an OCTET STRING *containing* a
///     SEQUENCE, so it is encoded twice — once as parameters, once as a
///     byte string. Other implementations rely on that.
///   * The scoped PDU is either a SEQUENCE or an OCTET STRING, decided by
///     the privacy flag, and the two are not interchangeable on the wire.
///   * `msgFlags` is a one-octet OCTET STRING, not an integer, and its
///     bits are auth 0x01, priv 0x02, reportable 0x04 (RFC 3412 §6.4).

///|
/// How well a message is protected, as the flags byte records it.
pub(all) enum SecurityLevel {
  /// No authentication, no privacy. Anything can claim to be anyone.
  NoAuthNoPriv
  /// Authenticated, not encrypted: the sender is proven, the contents
  /// are readable to anyone on the path.
  AuthNoPriv
  /// Authenticated and encrypted.
  AuthPriv
} derive(Eq, @debug.Debug)

///|
pub extend SecurityLevel with Eq::{not_equal, equal}

///|
pub extend SecurityLevel with @debug.Debug::{to_repr}

///|
/// A message's own flags, from which the level follows.
pub(all) struct MsgFlags {
  reportable : Bool
  authenticated : Bool
  encrypted : Bool
} derive(Eq, @debug.Debug)

///|
pub extend MsgFlags with Eq::{not_equal, equal}

///|
pub extend MsgFlags with @debug.Debug::{to_repr}

///|
/// The bits RFC 3412 §6.4 defines.
pub fn MsgFlags::to_byte(self : MsgFlags) -> Int {
  let mut byte = 0
  if self.authenticated {
    byte = byte | 0x01
  }
  if self.encrypted {
    byte = byte | 0x02
  }
  if self.reportable {
    byte = byte | 0x04
  }
  byte
}

///|
/// Read the flags from their wire byte. Bits beyond the three defined
/// ones are ignored rather than rejected: they are reserved, and a peer
/// setting one is not a reason to drop a message we can read.
pub fn MsgFlags::from_byte(byte : Int) -> MsgFlags {
  {
    authenticated: (byte & 0x01) != 0,
    encrypted: (byte & 0x02) != 0,
    reportable: (byte & 0x04) != 0,
  }
}

///|
/// The flags that go with a security level.
pub fn MsgFlags::of(level : SecurityLevel) -> MsgFlags {
  match level {
    NoAuthNoPriv =>
      { reportable: true, authenticated: false, encrypted: false, }
    AuthNoPriv => { reportable: true, authenticated: true, encrypted: false, }
    AuthPriv => { reportable: true, authenticated: true, encrypted: true, }
  }
}

///|
/// How much protection a level gives, so two of them can be compared.
/// USM refuses a message whose level is below the user's minimum
/// (RFC 3414 §3.2), which needs an ordering the enum itself does not
/// carry.
pub fn SecurityLevel::rank(self : SecurityLevel) -> Int {
  match self {
    NoAuthNoPriv => 0
    AuthNoPriv => 1
    AuthPriv => 2
  }
}

///|
/// The level the flags describe. A priv flag without auth is not a level
/// this library will produce, but a peer could send it; it is read as
/// AuthPriv because the message is encrypted either way.
pub fn MsgFlags::level(self : MsgFlags) -> SecurityLevel {
  if self.authenticated && self.encrypted {
    AuthPriv
  } else if self.authenticated {
    AuthNoPriv
  } else {
    NoAuthNoPriv
  }
}

///|
/// An authoritative engine: the identity a v3 message is scoped to, plus
/// the clock that makes its authentication checks work.
///
/// `boots` and `time` are not decoration. A receiver only accepts an
/// authenticated message whose time is within 150 seconds of its own
/// engine time (RFC 3414 §3.2), which is what stops a captured message
/// from being replayed.
pub(all) struct Engine {
  /// The engine id. Empty before discovery has run.
  id : Bytes
  boots : Int
  time : Int
} derive(Eq, @debug.Debug)

///|
pub extend Engine with Eq::{not_equal, equal}

///|
pub extend Engine with @debug.Debug::{to_repr}

///|
/// The engine before discovery: no id, no clock.
pub fn Engine::unknown() -> Engine {
  { id: b"", boots: 0, time: 0, }
}

///|
/// A PDU together with the context it applies to (RFC 3412 §6.2).
///
/// The context is what lets one engine serve several views of the same
/// tree; in practice a manager sets `context_name` to the empty string,
/// which is the default context, and leaves the engine id empty when
/// talking to the default context of the discovered engine.
pub(all) struct ScopedPdu {
  context_engine_id : Bytes
  context_name : Bytes
  pdu : @pdu.Pdu
} derive(Eq, @debug.Debug)

///|
pub extend ScopedPdu with Eq::{not_equal, equal}

///|
pub extend ScopedPdu with @debug.Debug::{to_repr}

///|
/// What a message's `msgData` holds. Reading a message does not tell you
/// what it says when it is encrypted, so the two cases are distinct
/// rather than one field that is sometimes meaningless.
pub(all) enum ScopedData {
  /// The scoped PDU, readable as sent.
  Plain(ScopedPdu)
  /// The serialized scoped PDU after encryption. It takes a privacy key
  /// to turn this back into a `Plain`.
  Encrypted(Bytes)
} derive(Eq, @debug.Debug)

///|
pub extend ScopedData with Eq::{not_equal, equal}

///|
pub extend ScopedData with @debug.Debug::{to_repr}

///|
/// A complete v3 message.
pub(all) struct V3Message {
  msg_id : Int
  /// How large a reply this sender can take, in octets. RFC 3412 §6.4
  /// sets the floor at 484.
  msg_max_size : Int
  flags : MsgFlags
  /// The security model: 3 is USM, the only one defined.
  security_model : Int
  engine : Engine
  user : Bytes
  /// The authenticator. Twelve octets for both USM protocols, or empty
  /// when the message is not authenticated.
  auth_params : Bytes
  /// The privacy parameters: the eight-octet salt AES needs, or empty.
  priv_params : Bytes
  data : ScopedData
} derive(Eq, @debug.Debug)

///|
pub extend V3Message with Eq::{not_equal, equal}

///|
pub extend V3Message with @debug.Debug::{to_repr}

///|
/// The USM security model number (RFC 3414 §1.1).
pub const USM_SECURITY_MODEL : Int = 3

///|
/// What net-snmp advertises, and a reasonable default: enough for any
/// reply that fits a datagram.
pub const DEFAULT_MAX_SIZE : Int = 65507

///|
/// How long a USM authenticator is, for both MD5 and SHA (RFC 3414
/// §6.3.1, §6.3.2). SHA-1's own digest is longer and is truncated.
pub const AUTH_PARAM_LENGTH : Int = 12

///|
/// The scoped PDU as a BER value: `SEQUENCE { engine id, name, PDU }`.
pub fn ScopedPdu::to_ber(self : ScopedPdu) -> @ber.BerValue {
  @ber.BerValue::Sequence([
    @ber.BerValue::OctetString(self.context_engine_id),
    @ber.BerValue::OctetString(self.context_name),
    self.pdu.to_ber(),
  ])
}

///|
/// The USM parameters as a BER value (RFC 3414 §2.4). They travel as an
/// OCTET STRING whose contents are this SEQUENCE.
fn usm_parameters(
  engine : Engine,
  user : Bytes,
  auth_params : Bytes,
  priv_params : Bytes,
) -> @ber.BerValue {
  @ber.BerValue::Sequence([
    @ber.BerValue::OctetString(engine.id),
    @ber.BerValue::Integer(engine.boots),
    @ber.BerValue::Integer(engine.time),
    @ber.BerValue::OctetString(user),
    @ber.BerValue::OctetString(auth_params),
    @ber.BerValue::OctetString(priv_params),
  ])
}

///|
/// Assemble the message with `msgData` supplied by the caller, because
/// whether that is a SEQUENCE or an OCTET STRING depends on the privacy
/// flag, and that is the one thing the encoder cannot infer.
fn V3Message::assemble(self : V3Message, data : @ber.BerValue) -> Bytes {
  @ber.BerValue::Sequence([
    @ber.BerValue::Integer(3),
    @ber.BerValue::Sequence([
      @ber.BerValue::Integer(self.msg_id),
      @ber.BerValue::Integer(self.msg_max_size),
      @ber.BerValue::OctetString(
        Bytes::from_array([self.flags.to_byte().to_byte()]),
      ),
      @ber.BerValue::Integer(self.security_model),
    ]),
    @ber.BerValue::OctetString(
      usm_parameters(self.engine, self.user, self.auth_params, self.priv_params).encode(),
    ),
    data,
  ]).encode()
}

///|
/// Encode the message as it stands, without touching the security
/// parameters.
///
/// For an authenticated message prefer `Seal::seal`, which fills in the
/// authenticator: a message encoded here with empty `auth_params` is not
/// authenticated, whatever its flags say.
pub fn V3Message::encode(self : V3Message) -> Bytes {
  match self.data {
    Plain(scoped) => self.assemble(scoped.to_ber())
    Encrypted(ciphertext) =>
      self.assemble(@ber.BerValue::OctetString(ciphertext))
  }
}

///|
/// Decode a v3 message.
///
/// An encrypted message decodes with its `msgData` as `Encrypted`: the
/// bytes are recovered exactly as sent, and `decrypt` turns them into a
/// `Plain` when the privacy key is available.
pub fn V3Message::decode(bytes : Bytes) -> V3Message raise V3Error {
  let outer = @ber.BerValue::decode(bytes) catch {
    e => raise V3Error::Malformed("the message is not valid BER: \{Repr(e)}")
  }
  let fields = match outer {
    @ber.BerValue::Sequence(items) => items
    _ => raise V3Error::Malformed("the message is not a SEQUENCE")
  }
  if fields.length() != 4 {
    raise V3Error::Malformed("a v3 message has four fields")
  }
  match fields[0] {
    @ber.BerValue::Integer(3) => ()
    @ber.BerValue::Integer(other) => raise V3Error::WrongVersion(other)
    _ => raise V3Error::Malformed("msgVersion is not an integer")
  }
  let global = match fields[1] {
    @ber.BerValue::Sequence(items) => items
    _ => raise V3Error::Malformed("msgGlobalData is not a SEQUENCE")
  }
  if global.length() != 4 {
    raise V3Error::Malformed("msgGlobalData has four fields")
  }
  let msg_id = int_of(global[0])
  let msg_max_size = int_of(global[1])
  let flags = MsgFlags::from_byte(
    match global[2] {
      @ber.BerValue::OctetString(b) =>
        if b.length() == 1 {
          b.at(0).to_uint().reinterpret_as_int()
        } else {
          raise V3Error::Malformed("msgFlags is one octet")
        }
      _ => raise V3Error::Malformed("msgFlags is not an OCTET STRING")
    },
  )
  let security_model = int_of(global[3])
  if security_model != USM_SECURITY_MODEL {
    raise V3Error::UnsupportedSecurityModel(security_model)
  }

  // The security parameters are a SEQUENCE that was encoded into an
  // OCTET STRING, so they have to be decoded twice.
  let raw_params = match fields[2] {
    @ber.BerValue::OctetString(b) => b
    _ =>
      raise V3Error::Malformed("msgSecurityParameters is not an OCTET STRING")
  }
  let usm = @ber.BerValue::decode(raw_params) catch {
    e =>
      raise V3Error::Malformed(
        "the USM parameters are not valid BER: \{Repr(e)}",
      )
  }
  let parts = match usm {
    @ber.BerValue::Sequence(items) => items
    _ => raise V3Error::Malformed("the USM parameters are not a SEQUENCE")
  }
  if parts.length() != 6 {
    raise V3Error::Malformed("the USM parameters have six fields")
  }
  let engine : Engine = {
    id: octets_of(parts[0]),
    boots: int_of(parts[1]),
    time: int_of(parts[2]),
  }
  let user = octets_of(parts[3])
  let auth_params = octets_of(parts[4])
  let priv_params = octets_of(parts[5])

  let data = match fields[3] {
    @ber.BerValue::OctetString(ciphertext) => Encrypted(ciphertext)
    @ber.BerValue::Sequence(items) => {
      if items.length() != 3 {
        raise V3Error::Malformed("a scoped PDU has three fields")
      }
      let pdu = @pdu.Pdu::from_ber(items[2]) catch {
        e => raise V3Error::Malformed("the PDU did not decode: \{Repr(e)}")
      }
      Plain({
        context_engine_id: octets_of(items[0]),
        context_name: octets_of(items[1]),
        pdu,
      })
    }
    _ =>
      raise V3Error::Malformed(
        "msgData is neither a SEQUENCE nor an OCTET STRING",
      )
  }

  {
    msg_id,
    msg_max_size,
    flags,
    security_model,
    engine,
    user,
    auth_params,
    priv_params,
    data,
  }
}

///|
/// An INTEGER field, or a failure if it is something else.
fn int_of(value : @ber.BerValue) -> Int raise V3Error {
  match value {
    @ber.BerValue::Integer(n) => n
    _ => raise V3Error::Malformed("expected an INTEGER")
  }
}

///|
/// An OCTET STRING field, or a failure if it is something else.
fn octets_of(value : @ber.BerValue) -> Bytes raise V3Error {
  match value {
    @ber.BerValue::OctetString(b) => b
    _ => raise V3Error::Malformed("expected an OCTET STRING")
  }
}
