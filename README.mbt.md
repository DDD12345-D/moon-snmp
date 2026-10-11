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
| `session` | done | Both halves of the conversation. As a client: `get`, `get_many`, `get_next`, `get_bulk`, `set`, and `walk` / `walk_bulk` for whole subtrees, with timeout, retry and stray-reply handling. As an agent: `trap_v1`, `trap_v2`, `inform`, and a `Receiver` that listens, checks the community and acknowledges informs. |
| `mib` | done | Well-known OIDs (MIB-II groups and scalars, the ifTable columns, the snmpTraps group) and value formatting: TimeTicks as `1:07:55.67`, interface status/type enums, IP and MAC addresses, and hex for non-printable byte strings. |

## Example

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

Querying an agent over UDP (JavaScript target only, for now):

```mbt nocheck
///|
fn sys_descr() -> String raise {
  let transport = @transport.Transport::open(0, 3000)
  let session = @session.Session::new(
    transport,
    "127.0.0.1",
    161,
    @pdu.V2c,
    b"public",
    3000, // ms per attempt
    2, // retries
    1000, // first request id
  )
  let vb = session.get(@oid.Oid::parse("1.3.6.1.2.1.1.1.0"))
  transport.close()
  match vb.value {
    @ber.BerValue::OctetString(b) => @utf8.decode_lossy(b)
    other => Repr(other).to_string()
  }
}
```

Walking a subtree, with the MIB-II constants and the value formatter:

```mbt nocheck
///|
fn system_group() -> Unit raise {
  let transport = @transport.Transport::open(0, 3000)
  let session = @session.Session::new(
    transport,
    "127.0.0.1",
    161,
    @pdu.V2c,
    b"public",
    3000,
    2,
    1000,
  )
  // `walk` GETs the root then iterates with GETNEXT, stopping when the
  // agent steps outside the subtree. `walk_bulk` does the same with
  // GETBULK, which is far fewer round trips on a large table.
  for entry in session.walk(@mib.system(), 0) {
    println("\{entry.name.to_dotted()} = \{@mib.format_value(entry.value)}")
  }
  transport.close()
}
```

`walk` of the system group on a stock agent prints the scalars, then the
`sysORTable` rows, when it reaches them:

```text
1.3.6.1.2.1.1.1.0 = "Linux testbox 6.1.0 x86_64"
1.3.6.1.2.1.1.3.0 = Timeticks: (407567) 1:07:55.67
1.3.6.1.2.1.1.5.0 = "testbox"
1.3.6.1.2.1.1.9.1.2.1 = OID: 1.3.6.1.6.3.10.3.1.1
```

## Notifications

The other direction: an agent telling a manager that something
happened. Receive them:

```mbt nocheck
///|
fn listen() -> Unit raise {
  // A receiver needs its own socket: a client querying an agent
  // would hold another.
  let socket = @transport.Transport::open(162, 3000)
  let receiver = @session.Receiver::new(socket, Some(b"public"))
  while true {
    let n = receiver.recv(5000) catch {
      // Nothing arrived in the window; keep listening.
      @session.SnmpError::NoResponse => continue
      e => raise e
    }
    println(
      "\{n.source_addr} says \{match n.trap_oid() {
        Some(o) => o.to_dotted()
        None => "?"
      }}",
    )
    for vb in n.varbinds() {
      println("  \{vb.name.to_dotted()} = \{@mib.format_value(vb.value)}")
    }
  }
}
```

Send them:

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
