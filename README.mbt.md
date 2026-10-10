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
| `session` | todo | UDP transport and the request/response exchange. |
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

## Development

Three checks must stay green; the pre-commit hook runs the first.

```sh
moon check --deny-warn
moon test
moon fmt --check
```
