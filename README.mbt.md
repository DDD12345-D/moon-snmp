# moon-snmp

Pure MoonBit implementation of the [SNMP](https://datatracker.ietf.org/doc/html/rfc1157) protocol client, for querying and monitoring network devices (switches, routers, printers, servers) — with no non-MoonBit code on the protocol path.

The library is under active development. This README tracks what has landed
so far.

## Packages

| Package | Status | What it does |
| --- | --- | --- |
| `oid` | done | Object identifiers: parse/build dotted-decimal text, render it back, compare numerically the way `walk` requires, and test subtree membership. |
| `ber` | done | BER encode/decode for the ASN.1 subset SNMP uses: the universal types (INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER, SEQUENCE), the SNMP application types (IpAddress, Counter32, Gauge32, TimeTicks, Opaque, Counter64), the v2c exception values, and an explicit-tag form for the PDU headers. |
| `pdu` | done | SNMP messages and PDUs for v1 and v2c: versions, the nine PDU types, error-status codes, var-binds, and the encode/decode of `SEQUENCE { version, community, PDU }`. |
| `transport` | done | A synchronous UDP transport for the JavaScript backend, plus the datagram and error types. Each socket gets its own worker thread behind a `SharedArrayBuffer`, so `send`/`recv` block the way a request/reply client wants and a process can hold several sockets. |
| `session` | done | Both halves of the conversation. As a client: `get`, `get_many`, `get_next`, `get_bulk`, `set` and `walk` / `walk_bulk` over v1, v2c and v3, with timeout, retry and stray-reply handling. As a notification originator: `trap_v1`, `trap_v2`, v3 traps and informs. As a receiver: `Receiver` for v1/v2c and `Receiver::v3`, which answers engine discovery and acknowledges informs. |
| `snmpv3` | done | SNMPv3 messages (RFC 3412) and the User-based Security Model (RFC 3414): engine discovery, key localization, HMAC-MD5-96 / HMAC-SHA-96 authentication, and AES-128 privacy (RFC 3826). DES is deliberately absent. |
| `mib` | done | Well-known OIDs (MIB-II groups and scalars, the ifTable columns, the snmpTraps group) and value formatting: TimeTicks as `1:07:55.67`, interface status/type enums, IP and MAC addresses, and hex for non-printable byte strings. |

## Examples

Each layer is usable on its own: `ber` and `oid` have no idea what SNMP
is, `pdu` knows the messages but not the network, `transport` knows the
network but not the protocol.

```mbt nocheck
///|
test "build and render sysDescr.0" {
  let oid = @oid.Oid::parse("1.3.6.1.2.1.1.1.0")
  inspect(oid.to_dotted(), content="1.3.6.1.2.1.1.1.0")

  // The wire form of that OID as a BER OBJECT IDENTIFIER.
  let value = @ber.BerValue::ObjectIdentifier(oid)
  inspect(value.encode().length(), content="10")
}
```

Four complete programs under [`examples/`](examples), each runnable
against a real device. They need the JavaScript target, which is the
module default, so no flag is required.

| Program | What it shows |
| --- | --- |
| `examples/query` | `get_many` — read a device's identity in one round trip. |
| `examples/walk_table` | `walk_bulk` — walk a MIB table and turn it into rows. |
| `examples/trap_listener` | `Receiver` — listen for v1/v2c traps and informs. |
| `examples/trap_listener_v3` | `Receiver::v3` — the same, as a v3 user, printing which engine each notification came from. |

`examples/query` against a net-snmp agent:

```console
$ moon run examples/query -- 192.0.2.10 public 161
asking 192.0.2.10:161 as "public"

sysDescr     "Linux snmpd 6.17.0 x86_64"
sysObjectID  OID: 1.3.6.1.4.1.8072.3.2.10
sysUpTime    Timeticks: (407567) 1:07:55.67
sysName      "moon-snmp-test-agent"
sysContact   "dev@example.com"
sysLocation  "Hackathon Lab"
```

The fixed values are the ones the fixture in `e2e/docker/snmpd.conf` sets;
`sysDescr` is whatever kernel string the device reports, and `sysUpTime`
counts from when its agent started.

`examples/walk_table`, which is where a table's shape on the wire
matters: cells arrive column-major, so a row per interface means
regrouping them by the index in the last arc.

```console
$ moon run examples/walk_table -- 192.0.2.10 public 161
ifNumber = 2

index  name  type              mtu    speed    status  address
1      lo    softwareLoopback  65536  10 Mb/s  up
2      eth0  ethernetCsmacd    1500   >4 Gb/s  up      1e:0c:c2:25:23:94
```

`examples/trap_listener` prints each notification it receives until it
goes quiet:

```console
$ moon run examples/trap_listener -- 1162
listening on udp/1162 for community "public"

--- 1: trap v2c from 192.0.2.10:52427
    what      1.3.6.1.6.3.1.1.5.3
    uptime    Timeticks: (171606) 0:28:36.06
    values
      1.3.6.1.2.1.1.3.0 = Timeticks: (171606) 0:28:36.06
      1.3.6.1.6.3.1.1.4.1.0 = OID: 1.3.6.1.6.3.1.1.5.3
--- 3: inform from 192.0.2.10:52429
    what      1.3.6.1.6.3.1.1.5.2
    reply     acknowledged
```

## Liveness

"Is the device there?" is one call, and it answers with the device's own
clock rather than a bare boolean:

```mbt nocheck
let alive = session.probe()
if alive.reachable {
  println("up for \{alive.uptime} hundredths of a second")
} else {
  println("no answer")
}
```

`probe` reads `sysUpTime.0` — one round trip, and a scalar every agent has
to implement — and reports silence as `reachable: false` instead of
raising, because a device that is down and a v1/v2c community that is
wrong look exactly the same on the wire (RFC 1157 §4.1). Everything else,
a malformed reply or an agent error, is still raised.

`V3Client::probe` is the same call with the user's keys, with one useful
difference: a wrong password is a `Security` error rather than silence,
because the device did answer.

## SNMPv3

v3 replaces the community with a user, and adds authentication and
privacy. A client has to discover the agent's engine id and clock before
it can authenticate anything — the keys are derived from the engine id,
and an authenticator is only accepted if the clock is close to the
agent's.

That clock is not a one-off handshake value. Every authenticated message
carries the sender's engine time, and both ends refuse a message more
than 150 seconds away from the clock they hold (RFC 3414 §3.2) — which is
what stops a recorded message from being replayed. The clocks here
advance with the wall clock on both sides: a client keeps the agent's
clock moving from the replies it receives and its own from the moment
`set_local_engine` is called, and a receiver keeps both. `set_clock` on
either side replaces the source, which is how the tests exercise the
window without waiting two and a half minutes.

```mbt nocheck
///|
fn read_over_v3() -> Unit raise {
  let socket = @transport.Transport::open(0, 3000)
  let security : @snmpv3.Security = {
    level: @snmpv3.AuthPriv,
    user: b"monitor",
    auth_protocol: @snmpv3.Sha1,
    auth_password: b"authpass",
    priv_protocol: @snmpv3.Aes128,
    priv_password: b"privpass",
  }
  // Discovery runs on the first request, so building a client cannot
  // fail on a network problem.
  let client = @session.V3Client::new(
    socket,
    "192.0.2.10",
    161,
    security,
    3000,
    2,
  )
  let vb = client.get(@mib.sys_name())
  println("\{client.engine().id.length()} octet engine id")
  println(@mib.format_value(vb.value))
  socket.close()
}
```

Changing the password to something wrong gives `SnmpError::Security`
rather than silence, and `@snmpv3.report_meaning(oid)` says which counter
the agent incremented — a wrong digest, an unknown user, or a clock too
far out of step. `examples/trap_listener_v3` is this listening end written
out, and the v3 suite in `e2e/v3query` is what drives the same path
against net-snmp.

The same client writes and walks as well. `set` sends a SetRequest; the
agent's access rules for that user decide whether it lands, so a
read-only user comes back as `AgentError` rather than a silent success.
`walk` and `walk_bulk` traverse a subtree with exactly the boundaries
the community session uses, including the end-of-subtree and
not-advancing checks.

## Notifications

The other direction: an agent telling a manager that something
happened. A `Receiver` is the listening end — `examples/trap_listener`
is that program written out.

```mbt nocheck
///|
fn report() -> Unit raise {
  let socket = @transport.Transport::open(0, 3000)
  let session = @session.Session::new(
    socket,
    "manager.example.com",
    162,
    @pdu.V2c,
    b"public",
    3000,
    2,
    1000,
  )
  // Fire-and-forget: `NoResponse` here means the send failed, not that
  // nobody listened.
  session.trap_v2(123456, @mib.link_down(), [
    @pdu.VarBind::new(@mib.if_descr(), @ber.BerValue::OctetString(b"eth0")),
  ])
  // An inform is acknowledged, so this one waits — and retries.
  let ack = session.inform(124000, @mib.warm_start(), [])
  println("acknowledged with \{ack.length()} varbind(s)")
  socket.close()
}
```

A trap is unacknowledged by design; an inform exists to be
acknowledged, and that is why only the inform waits. A v1 trap travels
as version 0 whatever the session is set to, because a v1 trap body in
a v2c message is not a valid combination.

The same two shapes go over v3, where the engine decides who is
authoritative. A trap is scoped to the *sender's* engine, so the sender
needs one of its own:

```mbt nocheck
///|
fn report_over_v3() -> Unit raise {
  let socket = @transport.Transport::open(0, 3000)
  let security : @snmpv3.Security = {
    level: @snmpv3.AuthPriv,
    user: b"monitor",
    auth_protocol: @snmpv3.Sha1,
    auth_password: b"authpass",
    priv_protocol: @snmpv3.Aes128,
    priv_password: b"privpass",
  }
  let client = @session.V3Client::new(
    socket,
    "manager.example.com",
    162,
    security,
    3000,
    2,
  )
  // The clock starts here and then advances with the machine: a
  // receiver records it and refuses anything more than 150 seconds off.
  let engine : @snmpv3.Engine = {
    id: b"\x80\x00\x1f\x88\x04collector",
    boots: 1,
    time: 0,
  }
  client.set_local_engine(engine)
  client.trap(123456, @mib.link_down(), [])
  // An inform is scoped to the *receiver's* engine, so this discovers
  // it first and then waits for the acknowledgement.
  let _ = client.inform(124000, @mib.warm_start(), [])
  socket.close()
}
```

On the listening side, `Receiver::v3` takes the user and this engine's
own identity. It answers discovery (that is how a sender can address an
inform to it), verifies a trap against the *sender's* engine id taken
from the message, and acknowledges an inform addressed to its own. A
receiver with an empty engine id can still take traps but cannot receive
informs: there is nothing to tell a sender.

When it refuses a message it says why, with a `usmStats` Report: a wrong
digest, an unknown user, a security level below the user's minimum, a
clock outside the window, a ciphertext that does not open. That Report
is the difference between a sender that knows to fix its password and
one that gives up on a timeout. Reports are unauthenticated where
nothing about the sender can be trusted yet, and signed where the
message itself was authentic.

## References

The protocol is defined by these documents, and the shape of this
library follows them rather than any one implementation:

- RFC 1157 — [A Simple Network Management Protocol](https://datatracker.ietf.org/doc/html/rfc1157) (SNMPv1, the v1 trap body).
- RFC 3416 — [Protocol Operations for SNMPv2](https://datatracker.ietf.org/doc/html/rfc3416) (the PDUs, error statuses, the v2c exceptions, the notification var-bind order).
- RFC 2578 — [SMIv2](https://datatracker.ietf.org/doc/html/rfc2578) (the application types and their ranges).
- RFC 1213 — [MIB-II](https://datatracker.ietf.org/doc/html/rfc1213) (the groups `mib` names).
- RFC 2576 — [Coexistence between SNMP versions](https://datatracker.ietf.org/doc/html/rfc2576) (the translation of a v1 trap into a trap OID).
- X.690 — the BER encoding rules the `ber` package implements.

Behaviour was checked against [net-snmp](https://www.net-snmp.org/)
(BSD-3-Clause) as the reference implementation, and its `snmpd`,
`snmptrapd` and `snmptrap` are what the end-to-end tests talk to. API
shape was informed by [gosnmp](https://github.com/gosnmp/gosnmp)
(BSD-2-Clause) and [snmpgo](https://github.com/k-sone/snmpgo)
(MIT); neither was copied from, and no code from either is included.

## Development

Three checks must stay green; the pre-commit hook runs the first.

```sh
moon check --deny-warn
moon test
moon fmt --check
```

The library targets the JavaScript backend: `transport` uses `node:dgram`
through a small bridge, and the other backends get a `%panic` stub rather
than a silent failure. Run anything that opens a socket with
`--target js`.

### End-to-end tests

The unit tests inject fakes, which makes them fast and deterministic and
also means they cannot see anything that only goes wrong over a real
socket. `e2e/` drives a real net-snmp implementation instead:

```sh
docker build -t moon-snmp-e2e e2e/docker

# Against an agent: 28 checks covering get/get_next/get_bulk, walk and
# walk_bulk, the v2c exceptions, and a wrong community.
docker run -d --name agent -p 16161:161/udp moon-snmp-e2e
moon run e2e/query --target js -- 127.0.0.1 16161

# Loopback: five notifications from one socket to another in one
# process, back to back. No docker needed, and it is the check that
# catches a transport dropping or duplicating datagrams.
moon run e2e/notify --target js -- loopback

# Sending to a real receiver, and receiving from a real sender.
docker run -d --name trapd -p 16162:162/udp moon-snmp-e2e \
  snmptrapd -f -Lo -n
moon run e2e/notify --target js -- send 127.0.0.1 16162
moon run e2e/notify --target js -- recv 16162 3
docker run --rm --add-host=host.docker.internal:host-gateway \
  moon-snmp-e2e snmptrap -v 2c -c public \
  host.docker.internal:16162 '' 1.3.6.1.6.3.1.1.5.1
```

Each harness exits non-zero when a check fails, so CI reads a status
rather than a log. `.github/workflows/ci.yml` runs these as five jobs:
formatting, types, unit tests, and the two end-to-end suites.

`e2e/docker/Dockerfile` takes its base image as a build argument, so the
same file works on a runner with plain Docker Hub access and behind a
network that needs a mirror:

```sh
docker build --build-arg BASE=<mirror>/library/alpine:latest \
  -t moon-snmp-e2e e2e/docker
```
