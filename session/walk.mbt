///|
/// One step of a walk: the OID the agent named plus the value it gave
/// for it. A walk is a list of these, in the agent's lexicographic
/// order.
pub(all) struct WalkEntry {
  name : @oid.Oid
  value : @ber.BerValue
} derive(Eq, @debug.Debug)

///|
pub extend WalkEntry with Eq::{not_equal, equal}

///|
pub extend WalkEntry with @debug.Debug::{to_repr}

///|
/// The three requests a walk is built from, as functions.
///
/// A community session and a v3 client put different things on the wire
/// — a community in one case, a security model and an engine in the
/// other — but the walk above them is the same protocol logic: where a
/// subtree ends, when an agent has stopped advancing, when the step
/// ceiling is reached. Taking the three primitives as arguments keeps
/// that logic in one place instead of two copies that can drift apart.
priv struct WalkAccess {
  get : (@oid.Oid) -> @pdu.VarBind raise SnmpError
  get_next : (@oid.Oid) -> @pdu.VarBind raise SnmpError
  get_bulk : (Array[@oid.Oid], Int, Int) -> Array[@pdu.VarBind] raise SnmpError
}

///|
/// Build a walk entry from a var-bind.
fn walk_entry_of(vb : @pdu.VarBind) -> WalkEntry {
  { name: vb.name, value: vb.value, }
}

///|
/// Whether a value is one of the v2c end-of-subtree markers. A GETNEXT
/// that runs off the end of the MIB returns `endOfMibView`, and a
/// request for something absent returns `noSuchObject` /
/// `noSuchInstance`; none of those are a real successor, so a walk must
/// stop rather than record them (RFC 3416 §4.2.2).
fn is_end_marker(value : @ber.BerValue) -> Bool {
  match value {
    @ber.BerValue::Tagged(tag, _) => tag == 0x80 || tag == 0x81 || tag == 0x82
    _ => false
  }
}

///|
/// Walk the subtree rooted at `root`, returning every leaf under it in
/// order, the way `snmpwalk` does.
///
/// The start is a GET of `root` itself: if the agent names a real
/// instance there (a scalar such as `...sysDescr.0`, or a table entry
/// OID), that value is the first result and the walk continues from it
/// with GETNEXT. If `root` is not an instance (a table or group root
/// answers with noSuchObject), nothing is emitted for it and the walk
/// starts at its first successor. This reproduces `snmpwalk
/// <oid>` for both a scalar and a whole group.
///
/// The walk stops when any of these happens:
///   - the agent names an OID outside `root` (the subtree is done);
///   - the agent returns an end-of-subtree marker;
///   - the agent fails to advance (a reply that is not greater than the
///     previous one, which a broken agent can do and which would
///     otherwise loop forever);
///   - `max_steps` OIDs have been collected.
///
/// `max_steps` is a deliberate ceiling: walking a large table over a
/// lossy link can take a long time, and a caller that wants to bound
/// the work should be able to. Pass `0` for no explicit limit beyond
/// the "not advancing" check.
fn walk_with(
  access : WalkAccess,
  root : @oid.Oid,
  max_steps : Int,
) -> Array[WalkEntry] raise SnmpError {
  let out : Array[WalkEntry] = []
  let mut cursor = root
  // GETNEXT semantics: each step names something strictly after the
  // cursor, and everything we keep is under `root`. Starting the cursor
  // one arc *below* the root is not possible in general, so the first
  // step is special: we GET the root itself and only keep it if the
  // agent treats it as an instance.
  let head = (access.get)(root)
  if !is_end_marker(head.value) && root.is_prefix_of(head.name) {
    out.push(walk_entry_of(head))
    cursor = head.name
    if max_steps != 0 && out.length() >= max_steps {
      return out
    }
  }
  // `cursor` always names the last accepted OID, so every later reply
  // must be strictly greater. A reply that is not means the agent is
  // not advancing and the walk must stop; once one entry has been
  // accepted there is no "first" to exempt, which is what keeps a
  // stuck agent from being recorded twice.
  while max_steps == 0 || out.length() < max_steps {
    let vb = (access.get_next)(cursor)
    if is_end_marker(vb.value) || !root.is_prefix_of(vb.name) {
      break
    }
    if vb.name.compare(cursor) <= 0 {
      break
    }
    out.push(walk_entry_of(vb))
    cursor = vb.name
  }
  out
}

///|
/// Walk a subtree with GETBULK instead of GETNEXT (RFC 3416 §4.2.3).
///
/// GETBULK returns up to `max_repetitions` successors per request, so a
/// large table needs far fewer round trips. v2c and v3 only: a v1 agent
/// does not know the request and will answer with an error, which
/// surfaces as `AgentError`.
///
/// The start and the boundaries match `walk`, but a single reply can
/// straddle the end of the subtree: the entries inside `root` are kept
/// and the rest of that reply is discarded.
fn walk_bulk_with(
  access : WalkAccess,
  root : @oid.Oid,
  max_repetitions : Int,
  max_steps : Int,
) -> Array[WalkEntry] raise SnmpError {
  let out : Array[WalkEntry] = []
  let mut cursor = root
  let head = (access.get)(root)
  if !is_end_marker(head.value) && root.is_prefix_of(head.name) {
    out.push(walk_entry_of(head))
    cursor = head.name
    if max_steps != 0 && out.length() >= max_steps {
      return out
    }
  }
  let mut done = false
  while !done && (max_steps == 0 || out.length() < max_steps) {
    let varbinds = (access.get_bulk)([cursor], 0, max_repetitions)
    if varbinds.length() == 0 {
      break
    }
    for vb in varbinds {
      if is_end_marker(vb.value) || !root.is_prefix_of(vb.name) {
        done = true
        break
      }
      // Same strictly-increasing requirement as `walk`.
      if vb.name.compare(cursor) <= 0 {
        done = true
        break
      }
      out.push(walk_entry_of(vb))
      cursor = vb.name
      if max_steps != 0 && out.length() >= max_steps {
        break
      }
    }
  }
  out
}

///|
/// The walk primitives of a community session.
fn[T : Transport] walk_access_of(session : Session[T]) -> WalkAccess {
  {
    get: fn(oid) raise SnmpError { session.get(oid) },
    get_next: fn(oid) raise SnmpError { session.get_next(oid) },
    get_bulk: fn(oids, non_repeaters, max_repetitions) raise SnmpError {
      session.get_bulk(oids, non_repeaters, max_repetitions)
    },
  }
}

///|
/// Walk the subtree rooted at `root` with GETNEXT, in agent order. See
/// `walk_with` for the boundaries and the stopping rules.
pub fn[T : Transport] Session::walk(
  self : Session[T],
  root : @oid.Oid,
  max_steps : Int,
) -> Array[WalkEntry] raise SnmpError {
  walk_with(walk_access_of(self), root, max_steps)
}

///|
/// Walk the subtree rooted at `root` with GETBULK, which needs fewer
/// round trips than `walk` on a large table. v2c only.
pub fn[T : Transport] Session::walk_bulk(
  self : Session[T],
  root : @oid.Oid,
  max_repetitions : Int,
  max_steps : Int,
) -> Array[WalkEntry] raise SnmpError {
  walk_bulk_with(walk_access_of(self), root, max_repetitions, max_steps)
}
