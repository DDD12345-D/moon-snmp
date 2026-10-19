///|
/// End-to-end v3 suite: drives a real net-snmp agent through engine
/// discovery, then asks the same question at each security level.
///
///   docker build -t moon-snmp-e2e e2e/docker
///   docker run -d --name snmpd -p 16161:161/udp moon-snmp-e2e
///   moon run e2e/v3query -- 127.0.0.1 16161
///
/// The user names and passwords are the ones `e2e/docker/snmpd.conf`
/// provisions, so the two files have to agree.
///
/// Exits non-zero if any check fails.

///|
const DEFAULT_HOST : String = "127.0.0.1"

///|
const DEFAULT_PORT : Int = 16161

///|
/// How long to wait for one reply, in milliseconds.
const TIMEOUT_MS : Int = 2000

///|
/// Retransmissions before giving up. Discovery costs one round trip on
/// its own, so a flaky first packet would otherwise fail the whole run.
const RETRIES : Int = 2

///|
/// The user with no authentication at all.
fn noauth_user() -> @snmpv3.Security {
  {
    level: @snmpv3.NoAuthNoPriv,
    user: b"e2e-noauth",
    auth_protocol: @snmpv3.None,
    auth_password: b"",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
}

///|
/// Authenticated with HMAC-MD5-96, not encrypted.
fn md5_user() -> @snmpv3.Security {
  {
    level: @snmpv3.AuthNoPriv,
    user: b"e2e-md5",
    auth_protocol: @snmpv3.Md5,
    auth_password: b"md5authpass",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
}

///|
/// Authenticated with HMAC-SHA-96, not encrypted.
fn sha_user() -> @snmpv3.Security {
  {
    level: @snmpv3.AuthNoPriv,
    user: b"e2e-sha",
    auth_protocol: @snmpv3.Sha1,
    auth_password: b"shaauthpass",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
}

///|
/// Authenticated with HMAC-SHA-256, not encrypted (RFC 7860).
fn sha256_user() -> @snmpv3.Security {
  {
    level: @snmpv3.AuthNoPriv,
    user: b"e2e-sha256",
    auth_protocol: @snmpv3.Sha256,
    auth_password: b"sha256authpass",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
}

///|
/// Authenticated with HMAC-SHA-512 (RFC 7860): a 48-octet
/// authenticator, four times the width MD5 uses.
fn sha512_user() -> @snmpv3.Security {
  {
    level: @snmpv3.AuthNoPriv,
    user: b"e2e-sha512",
    auth_protocol: @snmpv3.Sha512,
    auth_password: b"sha512authpass",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
}

///|
/// Authenticated with HMAC-SHA-256 and encrypted, which also proves the
/// privacy key is derived with the *authentication* hash (RFC 3414
/// §2.6): here a SHA-2 one.
fn sha256_priv_user() -> @snmpv3.Security {
  {
    level: @snmpv3.AuthPriv,
    user: b"e2e-sha256priv",
    auth_protocol: @snmpv3.Sha256,
    auth_password: b"sha256authpass",
    priv_protocol: @snmpv3.Aes128,
    priv_password: b"sha256privpass",
  }
}

///|
/// Authenticated and encrypted with AES-128.
fn priv_user() -> @snmpv3.Security {
  {
    level: @snmpv3.AuthPriv,
    user: b"e2e-priv",
    auth_protocol: @snmpv3.Sha1,
    auth_password: b"shaauthpass",
    priv_protocol: @snmpv3.Aes128,
    priv_password: b"shaprivpass",
  }
}

///|
fn main {
  let args = @support.Args::read()
  let host = args.text(2, DEFAULT_HOST)
  let port = args.number(3, DEFAULT_PORT)
  println("v3 suite against \{host}:\{port}\n")
  let checks = @support.Checks::new()
  // Opening a socket can fail, and `main` cannot raise, so the failure is
  // turned into a check like any other rather than into a stack trace.
  let socket = @transport.Transport::open(0, 3000) catch {
    e => {
      checks.bad("a socket could be opened", Repr(e).to_string())
      checks.finish("v3 suite")
      @transport.Transport::open(0, 1) catch {
        _ => abort("unreachable")
      }
    }
  }
  run(checks, socket, host, port) catch {
    e => checks.bad("the suite ran to completion", Repr(e).to_string())
  }
  socket.close()
  checks.finish("v3 suite")
}

///|
fn run(
  checks : @support.Checks,
  socket : @transport.Transport,
  host : String,
  port : Int,
) -> Unit raise {
  let sys_name = @mib.sys_name()

  // Discovery first, on its own, so a failure here is clearly a
  // discovery failure rather than a get that happened to go wrong.
  let probe = @session.V3Client::new(
    socket,
    host,
    port,
    noauth_user(),
    TIMEOUT_MS,
    RETRIES,
  )
  probe.discover()
  let engine = probe.engine()
  checks.that("discovery found an engine id", engine.id.length() > 0)
  checks.that("the reported engine clock is running", engine.time >= 0)
  println("       engine id   \{hex(engine.id)}")
  println("       engine boots \{engine.boots}  time \{engine.time}")

  // 1. No authentication. Worth having working: it is what discovery
  //    itself uses, and the easiest level to debug an agent with.
  let plain = probe.get(sys_name)
  checks.text(
    "noAuthNoPriv reads sysName.0",
    string_of(plain),
    "moon-snmp-test-agent",
  )

  // 2. Authentication with MD5: the key is localized to the engine, and
  //    the request carries an authenticator over the whole message.
  let md5 = @session.V3Client::new(
    socket,
    host,
    port,
    md5_user(),
    TIMEOUT_MS,
    RETRIES,
  )
  md5.discover()
  checks.text(
    "authNoPriv with HMAC-MD5-96 reads sysName.0",
    string_of(md5.get(sys_name)),
    "moon-snmp-test-agent",
  )

  // 3. The same with SHA-1, whose localized key is a different length —
  //    the two must not be mixed up.
  let sha = @session.V3Client::new(
    socket,
    host,
    port,
    sha_user(),
    TIMEOUT_MS,
    RETRIES,
  )
  sha.discover()
  checks.text(
    "authNoPriv with HMAC-SHA-96 reads sysName.0",
    string_of(sha.get(sys_name)),
    "moon-snmp-test-agent",
  )

  // 4. Authenticated *and* encrypted. This is the one that exercises the
  //    AES key, the initial vector from the engine clock, and the salt —
  //    and, on the way back, decryption of a message whose authenticity
  //    is checked before it is decrypted.
  let encrypted = @session.V3Client::new(
    socket,
    host,
    port,
    priv_user(),
    TIMEOUT_MS,
    RETRIES,
  )
  encrypted.discover()
  checks.text(
    "authPriv with AES-128 reads sysName.0",
    string_of(encrypted.get(sys_name)),
    "moon-snmp-test-agent",
  )

  // 5. A second request under the same keys: the salt must advance, or
  //    the keystream would repeat and the second message would be
  //    readable by anyone who saw the first.
  let second = encrypted.get(@mib.sys_descr())
  checks.that(
    "a second authPriv request works with a fresh salt",
    string_of(second).length() > 0,
  )

  // 6. Several values in one encrypted round trip, and a GETNEXT, so the
  //    scoped PDU is exercised with more than one shape inside it.
  let many = encrypted.get_many([@mib.sys_name(), @mib.sys_location()])
  checks.num("authPriv reads two values in one round trip", many.length(), 2)
  checks.text(
    "the second of them is sysLocation.0",
    string_of(
      match many.get(1) {
        Some(vb) => vb
        None => @pdu.VarBind::new(sys_name, @ber.BerValue::Null)
      },
    ),
    "Hackathon Lab",
  )
  let next = encrypted.get_next(@mib.sys_descr())
  checks.text(
    "authPriv GETNEXT steps to sysObjectID.0",
    next.name.to_dotted(),
    @mib.sys_object_id().to_dotted(),
  )

  // 7. A wrong password is refused by the agent, and that refusal has to
  //    reach the caller as a security error rather than as silence or as
  //    an empty answer. The agent answers with a Report counting a wrong
  //    digest, which is exactly what distinguishes a bad password from an
  //    unreachable agent.
  let wrong : @snmpv3.Security = {
    level: @snmpv3.AuthNoPriv,
    user: b"e2e-sha",
    auth_protocol: @snmpv3.Sha1,
    auth_password: b"not-the-password",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
  let bad = @session.V3Client::new(
    socket,
    host,
    port,
    wrong,
    TIMEOUT_MS,
    RETRIES,
  )
  bad.discover()
  let outcome = try {
    let _ = bad.get(sys_name)
    "answered"
  } catch {
    @session.SnmpError::Security(e) =>
      match e {
        @snmpv3.Report(oid, _) => "report: \{@snmpv3.report_meaning(oid)}"
        other => "security: \{Repr(other)}"
      }
    @session.SnmpError::NoResponse => "no response"
    e => "other: \{Repr(e)}"
  }
  checks.that(
    "a wrong password is refused as a security error",
    outcome != "answered" && outcome != "no response",
  )
  println("       wrong password -> \{outcome}")

  // 8. An unknown user is a different report from a wrong password, which
  //    is what lets a caller tell a typo in a password from a typo in a
  //    user name.
  let unknown : @snmpv3.Security = {
    level: @snmpv3.AuthNoPriv,
    user: b"nobody-here",
    auth_protocol: @snmpv3.Sha1,
    auth_password: b"shaauthpass",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
  let stranger = @session.V3Client::new(
    socket,
    host,
    port,
    unknown,
    TIMEOUT_MS,
    RETRIES,
  )
  stranger.discover()
  let stranger_outcome = try {
    let _ = stranger.get(sys_name)
    "answered"
  } catch {
    @session.SnmpError::Security(e) =>
      match e {
        @snmpv3.Report(oid, _) => "report: \{@snmpv3.report_meaning(oid)}"
        other => "security: \{Repr(other)}"
      }
    @session.SnmpError::NoResponse => "no response"
    e => "other: \{Repr(e)}"
  }
  checks.that(
    "an unknown user is refused as a security error",
    stranger_outcome != "answered",
  )
  println("       unknown user   -> \{stranger_outcome}")

  // 9. SET over v3. `snmpEnableAuthenTraps.0` is the writable scalar in
  //    MIB-II's snmp group, and it is *not* configured in snmpd.conf:
  //    net-snmp makes a system-group object read-only as soon as a
  //    config directive sets it, which is why the write is aimed here
  //    rather than at sysContact.
  let traps = authen_traps()
  let before = integer_of(encrypted.get(traps))
  checks.that(
    "snmpEnableAuthenTraps.0 reads as an INTEGER",
    before == 1 || before == 2,
  )
  let flipped = if before == 1 { 2 } else { 1 }
  let written = encrypted.set(traps, @ber.BerValue::Integer(flipped))
  checks.num("authPriv SET returns the written varbind", written.length(), 1)
  checks.that(
    "the agent committed the write",
    integer_of(encrypted.get(traps)) == flipped,
  )
  let _ = encrypted.set(traps, @ber.BerValue::Integer(before))
  checks.that(
    "the previous value can be restored",
    integer_of(encrypted.get(traps)) == before,
  )

  // 10. The same write as a read-only user must be refused by the
  //     agent. The permission lives on the agent, not in the request,
  //     so a client that reported success here would be inventing it.
  let mut refused = false
  try {
    let _ = sha.set(traps, @ber.BerValue::Integer(flipped))
  } catch {
    @session.SnmpError::AgentError(_, _) => refused = true
    _ => ()
  }
  checks.that("a read-only user cannot write", refused)

  // 11. WALK the system group over v3. The community suite checks the
  //     same subtree against net-snmp's snmpwalk in CI, so walking it
  //     here and comparing the two says the v3 path traverses the same
  //     tree rather than merely returning something.
  let community = @session.Session::new(
    socket,
    host,
    port,
    @pdu.V2c,
    b"public",
    TIMEOUT_MS,
    RETRIES,
    5000,
  )
  let reference = community.walk(@mib.system(), 0)
  let walked = encrypted.walk(@mib.system(), 0)
  checks.at_least(
    "authPriv walk of the system group finds its scalars",
    walked.length(),
    8,
  )
  checks.num(
    "authPriv walk finds as many entries as the community walk",
    walked.length(),
    reference.length(),
  )
  checks.that(
    "authPriv walk names the same OIDs in the same order",
    walk_names(walked) == walk_names(reference),
  )
  checks.text(
    "authPriv walk starts at the group's first scalar",
    match walked.get(0) {
      Some(e) => e.name.to_dotted()
      None => ""
    },
    @mib.sys_descr().to_dotted(),
  )
  let mut all_inside = true
  let mut ascending = true
  let mut previous : @oid.Oid? = None
  for entry in walked {
    if !@mib.system().is_prefix_of(entry.name) {
      all_inside = false
    }
    match previous {
      Some(p) => if entry.name.compare(p) <= 0 { ascending = false }
      None => ()
    }
    previous = Some(entry.name)
  }
  checks.that("every v3 walked entry is inside the subtree", all_inside)
  checks.that("the v3 walk never repeats or goes backwards", ascending)
  // The same machine-readable line the community suite prints, so a
  // script can compare either count with net-snmp's.
  println("v3 walk system: \{walked.length()} entries")

  // 12. Liveness over v3: the same one call, with the user's keys. A
  //     wrong password is a security error rather than silence — the
  //     device is there, and saying so is more useful than calling it
  //     down.
  let alive = encrypted.probe()
  checks.that("authPriv probe finds the engine", alive.reachable)
  checks.that("authPriv probe reports the agent's uptime", alive.uptime > 0)
  let wrong_alive = try {
    let l = bad.probe()
    if l.reachable {
      "reachable"
    } else {
      "unreachable"
    }
  } catch {
    @session.SnmpError::Security(_) => "security error"
    _ => "other"
  }
  checks.text(
    "a wrong password is a security error, not a silent device", wrong_alive, "security error",
  )

  // 13. GETBULK over the same subtree has to agree with the GETNEXT
  //     walk entry for entry: two traversals, one reply format apart.
  let bulked = encrypted.walk_bulk(@mib.system(), 10, 0)
  checks.num(
    "authPriv walk_bulk finds as many entries as walk",
    bulked.length(),
    walked.length(),
  )
  checks.that(
    "authPriv walk_bulk returns the same OIDs in the same order",
    walk_names(bulked) == walk_names(walked),
  )

  // 14. The SHA-2 family (RFC 7860). The authenticator is no longer
  //     twelve octets — 24 for SHA-256, 48 for SHA-512 — so this is also
  //     the check that the field width follows the protocol rather than
  //     a constant. Nothing here is shaped differently from the SHA-1
  //     case above; the agent is what makes it a real test.
  let sha256 : @session.V3Client[@transport.Transport] = @session.V3Client::new(
    socket,
    host,
    port,
    sha256_user(),
    TIMEOUT_MS,
    RETRIES,
  )
  sha256.discover()
  checks.text(
    "authNoPriv with HMAC-SHA-256 reads sysName.0",
    string_of(sha256.get(sys_name)),
    "moon-snmp-test-agent",
  )
  let sha512 : @session.V3Client[@transport.Transport] = @session.V3Client::new(
    socket,
    host,
    port,
    sha512_user(),
    TIMEOUT_MS,
    RETRIES,
  )
  sha512.discover()
  checks.text(
    "authNoPriv with HMAC-SHA-512 reads sysName.0",
    string_of(sha512.get(sys_name)),
    "moon-snmp-test-agent",
  )
  let sha256_priv : @session.V3Client[@transport.Transport] = @session.V3Client::new(
    socket,
    host,
    port,
    sha256_priv_user(),
    TIMEOUT_MS,
    RETRIES,
  )
  sha256_priv.discover()
  checks.text(
    "authPriv with SHA-256 and AES-128 reads sysName.0",
    string_of(sha256_priv.get(sys_name)),
    "moon-snmp-test-agent",
  )
}

///|
/// The list of OIDs of a walk, for comparing two walks.
fn walk_names(entries : Array[@session.WalkEntry]) -> Array[String] {
  let out : Array[String] = []
  for e in entries {
    out.push(e.name.to_dotted())
  }
  out
}

///|
/// 1.3.6.1.2.1.11.30.0, `snmpEnableAuthenTraps.0` (RFC 1907): the one
/// writable scalar in the snmp group, and therefore the object this
/// suite writes to prove a SetRequest is committed.
fn authen_traps() -> @oid.Oid {
  @oid.Oid::parse("1.3.6.1.2.1.11.30.0") catch {
    _ => abort("bad OID literal")
  }
}

///|
/// A varbind's value as an integer, or -1 when it is something else.
fn integer_of(vb : @pdu.VarBind) -> Int {
  match vb.value {
    @ber.BerValue::Integer(n) => n
    _ => -1
  }
}

///|
/// A varbind's value as text, for comparing against a known string.
fn string_of(vb : @pdu.VarBind) -> String {
  match vb.value {
    @ber.BerValue::OctetString(b) => @utf8.decode_lossy(b)
    other => @mib.format_value(other)
  }
}

///|
/// Lowercase hex, for printing an engine id.
fn hex(bytes : Bytes) -> String {
  let digits = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
  ]
  let out : Array[String] = []
  for i in 0..<bytes.length() {
    let b = bytes.at(i).to_uint().reinterpret_as_int()
    out.push(digits[b >> 4])
    out.push(digits[b & 0xF])
  }
  out.join("")
}
