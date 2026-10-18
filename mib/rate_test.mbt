///|
/// The two pieces of arithmetic a rate needs: a wrap-around difference
/// and a unit a person reads.

///|
test "a counter difference is taken modulo 2^32" {
  inspect(@mib.counter_delta(100, 200).to_int64(), content="100")
  // A 10G interface wraps in under four seconds, so this is the common
  // case under load, not a corner.
  inspect(@mib.counter_delta(4294967290U, 10U).to_int64(), content="16")
  // No movement is a legitimate answer, not an error.
  inspect(@mib.counter_delta(77U, 77U).to_int64(), content="0")
}

///|
test "a bit rate lands in the unit a person would use" {
  inspect(@mib.format_bit_rate(0L), content="0 b/s")
  inspect(@mib.format_bit_rate(300L), content="300 b/s")
  inspect(@mib.format_bit_rate(1500L), content="1.5 kb/s")
  inspect(@mib.format_bit_rate(12_500_000L), content="12.5 Mb/s")
  inspect(@mib.format_bit_rate(9_200_000_000L), content="9.2 Gb/s")
  // A rate that is not a number of bits is a bug upstream; say so rather
  // than print a plausible-looking negative.
  inspect(@mib.format_bit_rate(-5L), content="?")
}
