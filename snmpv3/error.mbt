///|
/// Errors from the v3 message layer and from USM.
pub(all) suberror V3Error {
  /// The bytes are not a v3 message this library can read. The string
  /// says which part was wrong, because "malformed" alone is not enough
  /// to debug an interoperability problem.
  Malformed(String)
  /// A message that is not version 3.
  WrongVersion(Int)
  /// A security model this library does not implement (only USM is
  /// defined).
  UnsupportedSecurityModel(Int)
  /// The message is authenticated and the authenticator did not check
  /// out, or it is not authenticated at all when one was required.
  AuthenticationFailed
  /// The message is encrypted and the privacy key does not open it.
  DecryptionFailed
  /// A message needs a privacy key or an engine discovery that this
  /// session has not obtained.
  NotReady(String)
  /// The agent answered with a Report PDU, which is how v3 reports a
  /// security problem rather than by dropping the message. The counter
  /// is the first var-bind's value, whose OID says what went wrong.
  Report(@oid.Oid, UInt)
} derive(@debug.Debug)

///|
pub extend V3Error with @debug.Debug::{to_repr}
