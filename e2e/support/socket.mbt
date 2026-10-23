///|
/// Opening a socket for a host the caller named on the command line.
///
/// A socket belongs to one address family, and a v4 socket cannot reach a
/// v6 address, so a harness that is pointed at `::1` has to open the
/// other one. Deciding that here keeps every suite able to run over
/// either family without each of them repeating the rule.

///|
/// Does this host look like an IPv6 literal?
///
/// A colon is the marker: a host name or a dotted-decimal address has
/// none, and a scoped address such as `fe80::1%eth0` does. This is a
/// shape check, not a parse — the socket reports a genuinely bad address
/// as a failure to bind, which is the error worth showing.
pub fn looks_like_ipv6(host : String) -> Bool {
  let mut found = false
  for c in host {
    if c == ':' {
      found = true
    }
  }
  found
}

///|
/// Open a client socket for `host`, on the family the address implies.
///
/// The port is left to the OS: a client wants an ephemeral one.
pub fn open_endpoint(host : String) -> @transport.Transport raise {
  if looks_like_ipv6(host) {
    @transport.Transport::open_ipv6(0, 3000)
  } else {
    @transport.Transport::open(0, 3000)
  }
}
