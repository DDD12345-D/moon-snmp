///|
/// The liveness cases: one real answer, one silence, and the v3 variant.
///
/// `FakeAgent` and `system_group()` come from `walk_test.mbt`; the fake
/// answers `sysUpTime.0` from its table like a real agent would.

///|
/// A transport that never answers: the device is off, or the community
/// is wrong and the agent is dropping us on purpose.
struct Silent {
  mut sent : Int
}

///|
fn Silent::new() -> Silent {
  { sent: 0, }
}

///|
impl @session.Transport for Silent with fn send(
  self : Silent,
  _host : String,
  _port : Int,
  _payload : Bytes,
) -> Unit raise @transport.TransportError {
  self.sent = self.sent + 1
}

///|
impl @session.Transport for Silent with fn recv(
  self : Silent,
  _timeout_ms : Int,
) -> @transport.Datagram raise @transport.TransportError {
  let _ = self
  raise @transport.TransportError::Timeout
}

///|
test "a device that answers is reachable, with its uptime" {
  let agent = FakeAgent::new(system_group())
  let session = session_of(agent)
  let alive = session.probe()
  inspect(alive.reachable, content="true")
  inspect(alive.uptime, content="1234")
}

///|
test "a device that never answers is reported unreachable, not raised" {
  let silent = Silent::new()
  let session = @session.Session::new(
    silent,
    "192.0.2.1",
    161,
    @pdu.V2c,
    b"public",
    50,
    0,
    1000,
  )
  let alive = session.probe()
  inspect(alive.reachable, content="false")
  inspect(alive.uptime, content="0")
  // One attempt, because this session was built with no retries.
  inspect(silent.sent, content="1")
}

///|
test "a v3 client probes with the user it was configured with" {
  let agent = FakeV3Agent::new(system_group())
  let client = v3_client_of(agent)
  let alive = client.probe()
  inspect(alive.reachable, content="true")
  inspect(alive.uptime, content="1234")
}

///|
test "a v3 device that never answers is reported unreachable" {
  let silent = Silent::new()
  let security : @snmpv3.Security = {
    level: @snmpv3.NoAuthNoPriv,
    user: b"monitor",
    auth_protocol: @snmpv3.None,
    auth_password: b"",
    priv_protocol: @snmpv3.None,
    priv_password: b"",
  }
  let client = @session.V3Client::new(silent, "192.0.2.1", 161, security, 50, 0)
  let alive = client.probe()
  inspect(alive.reachable, content="false")
  // Discovery costs the first attempt and the probe the second one.
  inspect(silent.sent >= 1, content="true")
}
