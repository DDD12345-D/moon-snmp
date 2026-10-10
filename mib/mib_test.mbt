///|
/// Tests for the MIB-II OID constants and the value formatters.

///|
test "the MIB-II OID constants round-trip through their text form" {
  // Every constant is a literal this package parses, so the cheapest
  // useful test is that the parsed text matches what a user expects to
  // see. A typo in a literal would show up here as a mismatch.
  inspect(@mib.sys_descr().to_dotted(), content="1.3.6.1.2.1.1.1.0")
  inspect(@mib.sys_object_id().to_dotted(), content="1.3.6.1.2.1.1.2.0")
  inspect(@mib.sys_up_time().to_dotted(), content="1.3.6.1.2.1.1.3.0")
  inspect(@mib.sys_contact().to_dotted(), content="1.3.6.1.2.1.1.4.0")
  inspect(@mib.sys_name().to_dotted(), content="1.3.6.1.2.1.1.5.0")
  inspect(@mib.sys_location().to_dotted(), content="1.3.6.1.2.1.1.6.0")
  inspect(@mib.sys_services().to_dotted(), content="1.3.6.1.2.1.1.7.0")
  inspect(@mib.if_number().to_dotted(), content="1.3.6.1.2.1.2.1.0")
  inspect(@mib.if_descr().to_dotted(), content="1.3.6.1.2.1.2.2.1.2")
  inspect(@mib.if_phys_address().to_dotted(), content="1.3.6.1.2.1.2.2.1.6")
  inspect(@mib.if_oper_status().to_dotted(), content="1.3.6.1.2.1.2.2.1.8")
  inspect(@mib.snmp_in_pkts().to_dotted(), content="1.3.6.1.2.1.11.1.0")
}

///|
test "group roots are prefixes of their members" {
  // A group constant is what you hand to `walk`, so it must be a prefix
  // of every scalar in the group.
  inspect(@mib.system().is_prefix_of(@mib.sys_descr()), content="true")
  inspect(@mib.system().is_prefix_of(@mib.sys_location()), content="true")
  inspect(@mib.interfaces().is_prefix_of(@mib.if_descr()), content="true")
  inspect(@mib.if_entry().is_prefix_of(@mib.if_descr()), content="true")
  inspect(@mib.if_entry().is_prefix_of(@mib.if_oper_status()), content="true")
  // And a scalar instance is not a prefix of the group above it.
  inspect(@mib.sys_descr().is_prefix_of(@mib.system()), content="false")
}

///|
test "system group members are contiguous under mib-2" {
  // The system scalars live at 1.3.6.1.2.1.1.<n>.0; walking the group
  // needs them ordered, which is what the OID comparison provides.
  let sys = @mib.system()
  inspect(sys.compare(@mib.sys_descr()) < 0, content="true")
  inspect(@mib.sys_descr().compare(@mib.sys_object_id()) < 0, content="true")
  inspect(@mib.sys_object_id().compare(@mib.sys_up_time()) < 0, content="true")
  inspect(
    @mib.sys_or_last_change().compare(@mib.interfaces()) < 0,
    content="true",
  )
}

///|
test "format_time_ticks matches snmpwalk's shape" {
  // 12345 hundredths = 123.45s = 2:03.45
  inspect(@mib.format_time_ticks(12345), content="0:02:03.45")
  // One hour, two minutes, three seconds, 45 hundredths.
  inspect(@mib.format_time_ticks(372345), content="1:02:03.45")
  inspect(@mib.format_time_ticks(0), content="0:00:00.00")
  // Exactly one second.
  inspect(@mib.format_time_ticks(100), content="0:00:01.00")
  // A little over a day of uptime is fine; hours are not capped.
  inspect(@mib.format_time_ticks(9000000), content="25:00:00.00")
}

///|
test "format_time_ticks_full carries both the raw value and the rendering" {
  inspect(
    @mib.format_time_ticks_full(12345),
    content="Timeticks: (12345) 0:02:03.45",
  )
}

///|
test "interface status and type enumerations render by name" {
  inspect(@mib.format_if_oper_status(1), content="up")
  inspect(@mib.format_if_oper_status(2), content="down")
  inspect(@mib.format_if_oper_status(7), content="lowerLayerDown")
  // An unknown code keeps its number rather than silently saying "up".
  inspect(@mib.format_if_oper_status(99), content="unknown(99)")

  inspect(@mib.format_if_admin_status(1), content="up")
  inspect(@mib.format_if_admin_status(9), content="unknown(9)")

  inspect(@mib.format_if_type(6), content="ethernetCsmacd")
  inspect(@mib.format_if_type(24), content="softwareLoopback")
  inspect(@mib.format_if_type(135), content="l2vlan")
  // An unlisted type prints as its IANA number.
  inspect(@mib.format_if_type(999), content="999")
}

///|
test "addresses render in their conventional forms" {
  inspect(@mib.format_ip_address(b"\xc0\xa8\x01\x01"), content="192.168.1.1")
  inspect(@mib.format_ip_address(b"\x00\x00\x00\x00"), content="0.0.0.0")
  // Wrong width is reported rather than mis-rendered.
  inspect(@mib.format_ip_address(b"\xc0\xa8\x01"), content="<ip 3 octets>")

  inspect(
    @mib.format_mac_address(b"\x02\x42\xac\x11\x00\x02"),
    content="02:42:ac:11:00:02",
  )
  inspect(@mib.format_mac_address(b""), content="")
}

///|
test "format_value picks the right rendering per type" {
  inspect(@mib.format_value(@ber.BerValue::Integer(42)), content="42")
  inspect(
    @mib.format_value(@ber.BerValue::OctetString(b"Linux box")),
    content="\"Linux box\"",
  )
  inspect(
    @mib.format_value(@ber.BerValue::Counter32(1234)),
    content="Counter32(1234)",
  )
  inspect(
    @mib.format_value(@ber.BerValue::Gauge32(1000000000)),
    content="Gauge32(1000000000)",
  )
  inspect(
    @mib.format_value(@ber.BerValue::TimeTicks(12345)),
    content="Timeticks: (12345) 0:02:03.45",
  )
  inspect(
    @mib.format_value(@ber.BerValue::ObjectIdentifier(@mib.sys_descr())),
    content="OID: 1.3.6.1.2.1.1.1.0",
  )
  inspect(
    @mib.format_value(@ber.BerValue::IpAddress(b"\x0a\x00\x00\x01")),
    content="10.0.0.1",
  )
  inspect(@mib.format_value(@ber.BerValue::Null), content="NULL")
}

///|
test "a non-printable octet string renders as hex, not mojibake" {
  // A MAC address is an OctetString but is not text; printing it as
  // text would put control characters in a log.
  inspect(
    @mib.format_value(@ber.BerValue::OctetString(b"\x02\x42\xac\x11\x00\x02")),
    content="Hex-STRING: 0242ac110002",
  )
  // An empty string is printable and prints as an empty quoted string.
  inspect(@mib.format_value(@ber.BerValue::OctetString(b"")), content="\"\"")
}

///|
test "the v2c exception values render as their human meaning" {
  inspect(
    @mib.format_value(@ber.BerValue::Tagged(0x80, [])),
    content="No Such Object available on this agent at this OID",
  )
  inspect(
    @mib.format_value(@ber.BerValue::Tagged(0x81, [])),
    content="No Such Instance currently exists at this OID",
  )
  inspect(
    @mib.format_value(@ber.BerValue::Tagged(0x82, [])),
    content="No more variables left in this MIB View",
  )
}
