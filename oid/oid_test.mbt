///|
test "parse and to_dotted round-trip" {
  let cases = [
    "1.3.6.1.2.1.1.1.0", "0.0", "1.2.3.4.5.6.7.8.9.10", "2.999999999", "2.0", "2.4294967215",
  ]
  for text in cases {
    let oid = @oid.Oid::parse(text)
    inspect(oid.to_dotted(), content=text)
  }
}

///|
test "parse rejects malformed text" {
  let bad_inputs = [
    "", // empty
     "1", // too short
     "3.1", // first component > 2
     "1.40", // second component >= 40 under root 1
     "0.40", "1..3", // empty component
     "1.3.", // trailing dot
     ".1.3", // leading dot
     "1.a.3", // stray character
     "1.3.x", "4294967296.1", // component overflow (2^32)
     "1.4294967296", " 1.3", // space
     "1.3 ", "1.-3",
  ]
  for text in bad_inputs {
    try {
      let _ = @oid.Oid::parse(text)
      fail("expected parse failure for: \{text}")
    } catch {
      _ => ()
    }
  }
}

///|
test "parse reports the specific error kind" {
  try {
    let _ = @oid.Oid::parse("")
    fail("expected Empty")
  } catch {
    @oid.Empty => ()
    e => fail("expected Empty, got \{e}")
  }
  try {
    let _ = @oid.Oid::parse("1.3.x")
    fail("expected InvalidCharacter")
  } catch {
    @oid.InvalidCharacter(_) => ()
    e => fail("expected InvalidCharacter, got \{e}")
  }
  try {
    let _ = @oid.Oid::parse("3.1")
    fail("expected InvalidFirstComponent")
  } catch {
    @oid.InvalidFirstComponent(_) => ()
    e => fail("expected InvalidFirstComponent, got \{e}")
  }
  try {
    let _ = @oid.Oid::parse("1.40")
    fail("expected InvalidSecondComponent")
  } catch {
    @oid.InvalidSecondComponent(_) => ()
    e => fail("expected InvalidSecondComponent, got \{e}")
  }
  try {
    let _ = @oid.Oid::parse("1.4294967296")
    fail("expected ComponentOverflow")
  } catch {
    @oid.ComponentOverflow => ()
    e => fail("expected ComponentOverflow, got \{e}")
  }
  try {
    let _ = @oid.Oid::parse("1")
    fail("expected TooShort")
  } catch {
    @oid.TooShort(_) => ()
    e => fail("expected TooShort, got \{e}")
  }
}

///|
test "from_parts validates the root pair" {
  // Legal: 80 + 6 = 86 fits the packed root subidentifier.
  let ok = @oid.Oid::from_parts([1, 3, 6])
  inspect(ok.to_dotted(), content="1.3.6")

  // 2.4294967215 is the largest legal pair: 80 + b == 0xFFFFFFFF.
  let edge = @oid.Oid::from_parts([2, 4294967215])
  inspect(edge.to_dotted(), content="2.4294967215")

  try {
    let _ = @oid.Oid::from_parts([2, 4294967216])
    fail("expected ComponentOverflow")
  } catch {
    @oid.ComponentOverflow => ()
    e => fail("expected ComponentOverflow, got \{e}")
  }
  try {
    let _ = @oid.Oid::from_parts([3, 1])
    fail("expected InvalidFirstComponent")
  } catch {
    @oid.InvalidFirstComponent(_) => ()
    e => fail("expected InvalidFirstComponent, got \{e}")
  }
  try {
    let _ = @oid.Oid::from_parts([1])
    fail("expected TooShort")
  } catch {
    @oid.TooShort(_) => ()
    e => fail("expected TooShort, got \{e}")
  }
  try {
    let _ = @oid.Oid::from_parts([0, 40, 1])
    fail("expected InvalidSecondComponent")
  } catch {
    @oid.InvalidSecondComponent(_) => ()
    e => fail("expected InvalidSecondComponent, got \{e}")
  }

  // 0.39 is the largest legal pair under root 0.
  inspect(@oid.Oid::from_parts([0, 39, 1]).to_dotted(), content="0.39.1")
}

///|
test "numeric compare beats string compare" {
  // 1.3.6.1.2.1.2 < 1.3.6.1.2.1.10 numerically, but the dotted
  // strings sort the other way ("2" > "10"). walk depends on this.
  let a = @oid.Oid::parse("1.3.6.1.2.1.2")
  let b = @oid.Oid::parse("1.3.6.1.2.1.10")
  inspect(a.compare(b), content="-1")
  inspect(b.compare(a), content="1")
  inspect(a.compare(a), content="0")
}

///|
test "a proper prefix sorts first" {
  let parent = @oid.Oid::parse("1.3.6.1")
  let child = @oid.Oid::parse("1.3.6.1.2.1.1")
  inspect(parent.compare(child), content="-1")
  inspect(child.compare(parent), content="1")
}

///|
test "large subidentifiers compare as unsigned" {
  // 4294967215 > 5 as UInt32, but as Int it would be negative.
  let a = @oid.Oid::parse("2.5")
  let b = @oid.Oid::parse("2.4294967215")
  inspect(a.compare(b), content="-1")
  inspect(b.compare(a), content="1")
}

///|
test "equality" {
  let a = @oid.Oid::parse("1.3.6.1.2.1.1.1.0")
  let b = @oid.Oid::parse("1.3.6.1.2.1.1.1.0")
  let c = @oid.Oid::parse("1.3.6.1.2.1.1.2.0")
  inspect(a == b, content="true")
  inspect(a != c, content="true")
}

///|
test "is_prefix_of recognises subtrees" {
  let system = @oid.Oid::parse("1.3.6.1.2.1.1")
  let sys_descr = @oid.Oid::parse("1.3.6.1.2.1.1.1.0")
  let sys_name = @oid.Oid::parse("1.3.6.1.2.1.1.5.0")
  let if_descr = @oid.Oid::parse("1.3.6.1.2.1.2.2.1.2.1")

  inspect(system.is_prefix_of(sys_descr), content="true")
  inspect(system.is_prefix_of(sys_name), content="true")
  // A different group is not under it.
  inspect(system.is_prefix_of(if_descr), content="false")
  // An OID is a prefix of itself, which `walk` relies on to accept the
  // root's own instance as the first entry.
  inspect(system.is_prefix_of(system), content="true")
  // The reverse never holds for a proper prefix.
  inspect(sys_descr.is_prefix_of(system), content="false")
  // It is not a plain string-prefix test: 1.3.6.1.2.1.11 is not under
  // 1.3.6.1.2.1.1 even though its text starts with those digits.
  let snmp = @oid.Oid::parse("1.3.6.1.2.1.11")
  inspect(system.is_prefix_of(snmp), content="false")
}
