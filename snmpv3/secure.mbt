///|
/// Sealing and opening a v3 message: encryption and authentication in the
/// order the protocol requires, and the checks that make them mean
/// something.
///
/// The order matters and is not symmetric with the reading side:
///
///   * sealing encrypts first and then authenticates, so the
///     authenticator covers the ciphertext;
///   * opening verifies first and then decrypts, so nothing is ever
///     acted upon before it is known to be authentic.
///
/// Getting the second one backwards is a real vulnerability class, not a
/// style question: decryption of unauthenticated data is how padding
/// oracles and the like work.

///|
/// A buffer of `n` zero octets, which is the placeholder an
/// authenticator is computed against (RFC 3414 §6.3.1).
fn zeros(n : Int) -> Bytes {
  Bytes::from_array(Array::make(n, 0))
}

///|
/// The message's scoped PDU, when it is readable.
///
/// An encrypted message has to be opened first; there is no accessor that
/// silently returns nonsense for it.
pub fn V3Message::scoped(self : V3Message) -> ScopedPdu? {
  match self.data {
    Plain(scoped) => Some(scoped)
    Encrypted(_) => None
  }
}

///|
/// Sign and, if the security level says so, encrypt a message.
///
/// `salt` is the eight-octet privacy parameter AES needs (RFC 3826
/// §3.1.2.1). It must be different for every message under the same key
/// and engine clock, or the keystream repeats and the encryption
/// collapses: the caller owns that counter, because only the caller knows
/// what it has already sent.
///
/// A message that is already sealed passes through the encryption step
/// untouched, so this is safe to call on either.
pub fn seal(
  message : V3Message,
  security : Security,
  keys : Keys,
  salt : Bytes,
) -> Bytes raise V3Error {
  // Encryption first, so the authenticator covers what is actually sent.
  let encrypted = match message.data {
    Encrypted(_) => message
    Plain(scoped) =>
      match security.priv_protocol {
        None => message
        Aes128 => {
          if salt.length() != 8 {
            raise V3Error::NotReady("the AES salt must be eight octets")
          }
          let plaintext = scoped.to_ber().encode()
          let ciphertext = encrypt_aes(
            plaintext,
            keys.priv_key,
            message.engine,
            salt,
          )
          { ..message, priv_params: salt, data: Encrypted(ciphertext), }
        }
      }
  }

  match security.auth_protocol {
    None => encrypted.encode()
    protocol => {
      // The authenticator is computed over the message with its own field
      // blanked, so the field has to be the right width before signing.
      // The field is as wide as the protocol's authenticator: twelve
      // octets for RFC 3414's two, 16 to 48 for the SHA-2 family.
      let blank = {
        ..encrypted,
        auth_params: zeros(protocol.auth_param_length()),
      }
      sign(blank.encode(), protocol, keys.auth_key)
    }
  }
}

///|
/// Verify and, if needed, decrypt a message.
///
/// The message is authenticated before it is decrypted, and an
/// authentication failure on a message whose flags claim authentication
/// is an error rather than a warning.
pub fn open(
  bytes : Bytes,
  security : Security,
  keys : Keys,
) -> V3Message raise V3Error {
  let message = V3Message::decode(bytes)

  // A peer that sends an authenticated message when we expect one, or
  // one that claims authentication, is held to it.
  let claims_authentication = message.flags.authenticated
  if claims_authentication || security.auth_protocol != None {
    if security.auth_protocol == None {
      raise V3Error::NotReady(
        "the agent authenticated the message but no authentication key is configured",
      )
    }
    if !verify(bytes, security.auth_protocol, keys.auth_key) {
      raise V3Error::AuthenticationFailed
    }
  }

  match message.data {
    Plain(_) => message
    Encrypted(ciphertext) =>
      match security.priv_protocol {
        None =>
          raise V3Error::NotReady(
            "the message is encrypted but no privacy protocol is configured",
          )
        Aes128 => {
          let plaintext = decrypt_aes(
            ciphertext,
            keys.priv_key,
            message.engine,
            message.priv_params,
          )
          let value = @ber.BerValue::decode(plaintext) catch {
            _ => raise V3Error::DecryptionFailed
          }
          let fields = match value {
            @ber.BerValue::Sequence(items) => items
            _ => raise V3Error::DecryptionFailed
          }
          if fields.length() != 3 {
            raise V3Error::DecryptionFailed
          }
          let pdu = @pdu.Pdu::from_ber(fields[2]) catch {
            _ => raise V3Error::DecryptionFailed
          }
          let context_engine_id = match fields[0] {
            @ber.BerValue::OctetString(b) => b
            _ => raise V3Error::DecryptionFailed
          }
          let context_name = match fields[1] {
            @ber.BerValue::OctetString(b) => b
            _ => raise V3Error::DecryptionFailed
          }
          { ..message, data: Plain({ context_engine_id, context_name, pdu, }), }
        }
      }
  }
}

///|
/// What a Report PDU is reporting: the counter's OID and its value.
///
/// A Report is how v3 says "I could not process this" — an unknown engine
/// id, an unknown user, a clock that is too far out, a wrong digest. It
/// arrives authenticated when it concerns authentication, and the OID
/// says which counter incremented, so a client can tell a wrong password
/// from a stale engine clock.
pub fn V3Message::report(self : V3Message) -> (@oid.Oid, UInt)? {
  match self.data {
    Encrypted(_) => None
    Plain(scoped) =>
      match scoped.pdu {
        @pdu.Generic(p) =>
          match p.pdu_type {
            @pdu.Report =>
              match p.varbinds.get(0) {
                Some(vb) =>
                  match vb.value {
                    @ber.BerValue::Counter32(n) => Some((vb.name, n))
                    // A few counters are of other unsigned types; the
                    // number is what a caller wants either way.
                    @ber.BerValue::Gauge32(n) => Some((vb.name, n))
                    @ber.BerValue::TimeTicks(n) => Some((vb.name, n))
                    @ber.BerValue::Integer(n) =>
                      Some((vb.name, n.reinterpret_as_uint()))
                    _ => None
                  }
                None => None
              }
            _ => None
          }
        _ => None
      }
  }
}

///|
/// A Report as an error, or nothing when the message is not one.
///
/// A Report is the agent saying no in a way the caller must see: a wrong
/// digest, an unknown user, a clock too far out. Keeping the counter's OID
/// with the error is what lets a caller tell those apart rather than
/// treating every refusal as a bad password.
pub fn report_error(message : V3Message) -> V3Error? {
  match message.report() {
    Some((oid, count)) => Some(V3Error::Report(oid, count))
    None => None
  }
}

///|
/// Whether a message carries a Report PDU.
pub fn V3Message::is_report(self : V3Message) -> Bool {
  match self.report() {
    Some(_) => true
    None => false
  }
}

///|
/// The OIDs a Report uses, so a caller can say what went wrong in words
/// rather than in numbers (RFC 3414 §5).
pub fn report_meaning(oid : @oid.Oid) -> String {
  let known : Array[(@oid.Oid, String)] = [
    (
      usm_stats_unsupported_sec_levels(),
      "the security level is not supported for this user",
    ),
    (usm_stats_not_in_time_windows(), "the engine clock is out of step"),
    (usm_stats_unknown_user_names(), "no such user"),
    (usm_stats_unknown_engine_ids(), "the engine id is not known"),
    (usm_stats_wrong_digests(), "the authenticator did not match"),
    (usm_stats_decryption_errors(), "the message could not be decrypted"),
    (usm_stats_unknown_security_models(), "the security model is not supported"),
    (usm_stats_invalid_msgs(), "the message was invalid"),
    (usm_stats_unknown_pdu_handlers(), "the PDU type is not handled"),
  ]
  for entry in known {
    let (candidate, meaning) = entry
    if oid.compare(candidate) == 0 {
      return meaning
    }
  }
  oid.to_dotted()
}

///|
/// The reasons USM has for refusing a message, each with its own
/// `usmStats` counter (RFC 3414 §5).
///
/// An authoritative engine does not drop a message silently: it answers
/// with a Report naming the counter it incremented, so the sender learns
/// whether its password, its clock, or its idea of the engine is wrong.
pub(all) enum ReportKind {
  /// The security level is below what this user is allowed to use.
  UnsupportedSecLevels
  /// The engine clock is outside the 150-second window.
  NotInTimeWindows
  /// No such user on this engine.
  UnknownUserNames
  /// The sender does not know this engine yet — the discovery answer.
  UnknownEngineIds
  /// The authenticator did not match.
  WrongDigests
  /// The ciphertext did not open.
  DecryptionErrors
} derive(Eq, @debug.Debug)

///|
pub extend ReportKind with Eq::{not_equal, equal}

///|
pub extend ReportKind with @debug.Debug::{to_repr}

///|
/// The counter OID a Report of this kind carries.
pub fn ReportKind::oid(self : ReportKind) -> @oid.Oid {
  match self {
    UnsupportedSecLevels => usm_stats_unsupported_sec_levels()
    NotInTimeWindows => usm_stats_not_in_time_windows()
    UnknownUserNames => usm_stats_unknown_user_names()
    UnknownEngineIds => usm_stats_unknown_engine_ids()
    WrongDigests => usm_stats_wrong_digests()
    DecryptionErrors => usm_stats_decryption_errors()
  }
}

///|
/// The number of kinds, for a counter table.
pub const REPORT_KINDS : Int = 6

///|
/// A stable slot per kind, so a receiver can keep one counter for each
/// without a map.
pub fn ReportKind::slot(self : ReportKind) -> Int {
  match self {
    UnsupportedSecLevels => 0
    NotInTimeWindows => 1
    UnknownUserNames => 2
    UnknownEngineIds => 3
    WrongDigests => 4
    DecryptionErrors => 5
  }
}

///|
/// One of the `usmStats` counters, 1.3.6.1.6.3.15.1.1.<n>.0.
fn usm_stat(n : UInt) -> @oid.Oid {
  let parts : Array[UInt] = [1U, 3U, 6U, 1U, 6U, 3U, 15U, 1U, 1U, n, 0U]
  @oid.Oid::from_parts(parts) catch {
    _ => abort("the usmStats OID is not valid")
  }
}

///|
/// 1.3.6.1.6.3.15.1.1.1.0
pub fn usm_stats_unsupported_sec_levels() -> @oid.Oid {
  usm_stat(1U)
}

///|
/// 1.3.6.1.6.3.15.1.1.2.0
pub fn usm_stats_not_in_time_windows() -> @oid.Oid {
  usm_stat(2U)
}

///|
/// 1.3.6.1.6.3.15.1.1.3.0
pub fn usm_stats_unknown_user_names() -> @oid.Oid {
  usm_stat(3U)
}

///|
/// 1.3.6.1.6.3.15.1.1.4.0
pub fn usm_stats_unknown_engine_ids() -> @oid.Oid {
  usm_stat(4U)
}

///|
/// 1.3.6.1.6.3.15.1.1.5.0
pub fn usm_stats_wrong_digests() -> @oid.Oid {
  usm_stat(5U)
}

///|
/// 1.3.6.1.6.3.15.1.1.6.0
pub fn usm_stats_decryption_errors() -> @oid.Oid {
  usm_stat(6U)
}

///|
/// 1.3.6.1.6.3.15.1.1.7.0
pub fn usm_stats_unknown_security_models() -> @oid.Oid {
  usm_stat(7U)
}

///|
/// 1.3.6.1.6.3.15.1.1.8.0
pub fn usm_stats_invalid_msgs() -> @oid.Oid {
  usm_stat(8U)
}

///|
/// 1.3.6.1.6.3.15.1.1.9.0
pub fn usm_stats_unknown_pdu_handlers() -> @oid.Oid {
  usm_stat(9U)
}
