///|
/// The pairing and the division, with numbers a person can check by hand.

///|
test "a rate pairs two samples and divides by the time that passed" {
  let first : Array[Counters] = [
    { index: 1, descr: "eth0", in_octets: 1000U, out_octets: 2000U, },
  ]
  let second : Array[Counters] = [
    { index: 1, descr: "eth0", in_octets: 1_251_000U, out_octets: 2000U, },
  ]
  let rates = rates_between(first, second, 1000L)
  inspect(rates.length(), content="1")
  // 1,250,000 octets in one second is 10,000,000 bits per second.
  inspect(rates[0].in_bps, content="10000000")
  inspect(rates[0].out_bps, content="0")
  inspect(@mib.format_bit_rate(rates[0].in_bps), content="10.0 Mb/s")
}

///|
test "a counter that wrapped still gives the right difference" {
  // 2^32 - 4_294_967_000 is 296, plus 100 after the wrap is 396 octets.
  let first : Array[Counters] = [
    { index: 2, descr: "eth1", in_octets: 4_294_967_000U, out_octets: 5U, },
  ]
  let second : Array[Counters] = [
    { index: 2, descr: "eth1", in_octets: 100U, out_octets: 6U, },
  ]
  let rates = rates_between(first, second, 1000L)
  inspect(rates[0].in_bps, content="3168")
  inspect(rates[0].out_bps, content="8")
}

///|
test "an interface that disappeared between samples gets no rate" {
  let first : Array[Counters] = [
    { index: 1, descr: "eth0", in_octets: 0U, out_octets: 0U, },
    { index: 3, descr: "usb0", in_octets: 0U, out_octets: 0U, },
  ]
  let second : Array[Counters] = [
    { index: 1, descr: "eth0", in_octets: 10U, out_octets: 10U, },
  ]
  let rates = rates_between(first, second, 1000L)
  inspect(rates.length(), content="1")
  inspect(rates[0].index, content="1")
}
