///|
/// The clock rules of USM (RFC 3414 §3.2).
///
/// The authenticator proves *who* sent a message; the engine clock proves
/// it was sent *now*. Without the second check a recorded message can be
/// replayed and will authenticate perfectly, which is why RFC 3414 makes
/// the time window mandatory for authenticated messages rather than
/// optional.

///|
/// How far a message's clock may be from the receiver's before the
/// message is refused (RFC 3414 §3.2, `usmStatsNotInTimeWindows`).
pub const TIME_WINDOW_S : Int = 150

///|
/// What a received engine clock says, relative to the one we hold.
pub(all) enum Timeliness {
  /// Within the window: accept.
  Fresh
  /// The peer restarted — its boots advanced. Accept, and reset to it.
  Restarted
  /// Older than the window: refuse. This is the anti-replay rule.
  Stale
} derive(Eq, @debug.Debug)

///|
pub extend Timeliness with Eq::{not_equal, equal}

///|
pub extend Timeliness with @debug.Debug::{to_repr}

///|
/// Judge a message from a peer whose clock we have been keeping.
///
/// Only "older than the window" is refused, which is the rule net-snmp
/// implements: a peer whose clock jumps ahead is taken at its word and
/// its new clock is recorded, while a message more than 150 seconds
/// behind the clock the peer itself has been keeping is either a replay
/// or something from before it restarted, and neither can be trusted.
///
/// `reference` is that remembered clock advanced to now, not the raw
/// value we last saw — a clock that does not advance would make every
/// message look current.
pub fn peer_timeliness(received : Engine, reference : Engine) -> Timeliness {
  if received.boots < reference.boots {
    Stale
  } else if received.boots > reference.boots {
    Restarted
  } else if reference.time - received.time > TIME_WINDOW_S {
    Stale
  } else {
    Fresh
  }
}

///|
/// Judge a message that claims *our* engine as authoritative.
///
/// Here we are the clock, so a sender has to use the boots and time we
/// told it about and stay inside the window in both directions: a
/// message dated in the future is as wrong as one dated in the past.
pub fn local_timeliness(received : Engine, ours : Engine) -> Timeliness {
  if received.boots != ours.boots {
    Stale
  } else if (ours.time - received.time).abs() > TIME_WINDOW_S {
    Stale
  } else {
    Fresh
  }
}

///|
/// An engine clock moved forward by the time that has passed since it was
/// recorded.
///
/// The fractional second is dropped: `engineTime` is whole seconds, and
/// truncating keeps the clock from running ahead of the wall clock a peer
/// will compare it against.
pub fn Engine::advanced(self : Engine, elapsed_ms : Int64) -> Engine {
  if elapsed_ms <= 0L {
    return self
  }
  { ..self, time: self.time + (elapsed_ms / 1000L).to_int(), }
}
