///|
/// The pairing and the division, with numbers a person can check by hand.

///|
test "a rate pairs two samples and divides by the time that passed" {
  let first : Array[Counters] = [
    { index: 1, descr: "eth0", in_octets: 1000, out_octets: 2000, },
  ]
  let second : Array[Counters] = [
    { index: 1, descr: "eth0", in_octets: 1_251_000, out_octets: 2000, },
  ]
  let rates = rates_between(first, second, 1000L, false)
  inspect(rates.length(), content="1")
  // 1,250,000 octets in one second is 10,000,000 bits per second.
  inspect(rates[0].in_bps, content="10000000")
  inspect(rates[0].out_bps, content="0")
  inspect(@mib.format_bit_rate(rates[0].in_bps), content="10.0 Mb/s")
}

///|
test "a 32-bit counter that wrapped still gives the right difference" {
  // 2^32 - 4_294_967_000 is 296, plus 100 after the wrap is 396 octets.
  let first : Array[Counters] = [
    { index: 2, descr: "eth1", in_octets: 4_294_967_000, out_octets: 5, },
  ]
  let second : Array[Counters] = [
    { index: 2, descr: "eth1", in_octets: 100, out_octets: 6, },
  ]
  let rates = rates_between(first, second, 1000L, false)
  inspect(rates[0].in_bps, content="3168")
  inspect(rates[0].out_bps, content="8")
}

///|
test "a 64-bit counter above 2^32 divides the same way" {
  // 2^40 is a value a 32-bit counter cannot hold at all, which is the
  // whole reason the wide columns exist.
  let first : Array[Counters] = [
    {
      index: 1,
      descr: "eth0",
      in_octets: 1_099_511_627_776,
      out_octets: 1_099_511_627_776,
    },
  ]
  let second : Array[Counters] = [
    {
      index: 1,
      descr: "eth0",
      in_octets: 1_099_512_877_776,
      out_octets: 1_099_511_627_776,
    },
  ]
  let rates = rates_between(first, second, 1000L, true)
  inspect(rates[0].in_bps, content="10000000")
  inspect(rates[0].out_bps, content="0")
}

///|
test "an interface that disappeared between samples gets no rate" {
  let first : Array[Counters] = [
    { index: 1, descr: "eth0", in_octets: 0, out_octets: 0, },
    { index: 3, descr: "usb0", in_octets: 0, out_octets: 0, },
  ]
  let second : Array[Counters] = [
    { index: 1, descr: "eth0", in_octets: 10, out_octets: 10, },
  ]
  let rates = rates_between(first, second, 1000L, true)
  inspect(rates.length(), content="1")
  inspect(rates[0].index, content="1")
}
