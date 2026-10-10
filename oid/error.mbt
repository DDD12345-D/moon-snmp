///|
/// Errors raised while parsing or validating object identifiers.
pub suberror OidError {
  /// The input text is empty.
  Empty
  /// A byte that is neither a decimal digit nor a dot, at this offset.
  InvalidCharacter(Int)
  /// Fewer than two subidentifiers (given count).
  TooShort(Int)
  /// The first component is not 0, 1, or 2.
  InvalidFirstComponent(UInt)
  /// The second component is 40 or more under root 0 or 1.
  InvalidSecondComponent(UInt)
  /// A component does not fit in an unsigned 32-bit subidentifier.
  ComponentOverflow
} derive(@debug.Debug)

///|
pub extend OidError with @debug.Debug::{to_repr}
