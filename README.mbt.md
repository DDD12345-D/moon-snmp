# moon-snmp

Pure MoonBit implementation of the [SNMP](https://datatracker.ietf.org/doc/html/rfc1157) protocol client, for querying and monitoring network devices (switches, routers, printers, servers) — with no non-MoonBit code on the protocol path.

The library is under active development. This README tracks what has landed
so far.

## Packages

| Package | Status | What it does |
| --- | --- | --- |
| `oid` | done | Object identifiers: parse/build dotted-decimal text, render it back, and compare numerically the way `walk` requires. |
| `ber` | done | BER encode/decode for the ASN.1 subset SNMP uses: the universal types (INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER, SEQUENCE), the SNMP application types (IpAddress, Counter32, Gauge32, TimeTicks, Opaque, Counter64), and an explicit-tag form for the PDU headers. |
| `pdu` | done | SNMP messages and PDUs for v1 and v2c: versions, the nine PDU types, error-status codes, var-binds, and the encode/decode of `SEQUENCE { version, community, PDU }`. |
| `transport` | done | A synchronous UDP transport for the JavaScript backend, plus the datagram and error types. The socket lives in a node worker thread behind a `SharedArrayBuffer`, so `send`/`recv` block the way a request/reply client wants. |
| `session` | done | The v1/v2c client: a session owns the agent address, community, version and the request-id counter, and exposes `get`, `get_many`, `get_next`, `get_bulk` and `set`. Handles timeouts, retries and stray replies. |
| `mib` | todo | Common MIB values and formatting helpers. |

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
