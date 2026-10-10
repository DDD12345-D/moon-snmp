///|
/// Well-known OIDs from MIB-II (RFC 1213 / RFC 4293) and the SNMPv2
/// SMI, so callers do not have to spell them out as strings.
///
/// These are functions rather than constants because `Oid::parse` can
/// fail: each one is a fixed string this library also tests, so the
/// abort on a bad literal is a "cannot happen" that a test would catch
/// immediately.

///|
/// Parse a literal OID known to be valid.
fn lit(dotted : String) -> @oid.Oid {
  @oid.Oid::parse(dotted) catch {
    _ => abort("mib: internal OID literal is not valid: \{dotted}")
  }
}

///|
/// `system` group root, 1.3.6.1.2.1.1. Walking this yields every system
/// scalar (and the sysORTable entries that live under it).
pub fn system() -> @oid.Oid {
  lit("1.3.6.1.2.1.1")
}

///|
/// sysDescr.0 — a textual description of the entity (RFC 1213 §6.1.2).
pub fn sys_descr() -> @oid.Oid {
  lit("1.3.6.1.2.1.1.1.0")
}

///|
/// sysObjectID.0 — the vendor's authoritative identification of the
/// network management subsystem (RFC 1213 §6.1.3).
pub fn sys_object_id() -> @oid.Oid {
  lit("1.3.6.1.2.1.1.2.0")
}

///|
/// sysUpTime.0 — time since the network management portion of the
/// system was last re-initialised, in TimeTicks (hundredths of a
/// second; RFC 1213 §6.1.6).
pub fn sys_up_time() -> @oid.Oid {
  lit("1.3.6.1.2.1.1.3.0")
}

///|
/// sysContact.0 — the contact person for this managed node.
pub fn sys_contact() -> @oid.Oid {
  lit("1.3.6.1.2.1.1.4.0")
}

///|
/// sysName.0 — an administratively-assigned name for this node.
pub fn sys_name() -> @oid.Oid {
  lit("1.3.6.1.2.1.1.5.0")
}

///|
/// sysLocation.0 — the physical location of this node.
pub fn sys_location() -> @oid.Oid {
  lit("1.3.6.1.2.1.1.6.0")
}

///|
/// sysServices.0 — a value describing the set of services this node
/// offers (RFC 1213 §6.1.7).
pub fn sys_services() -> @oid.Oid {
  lit("1.3.6.1.2.1.1.7.0")
}

///|
/// sysORLastChange.0 — the value of sysUpTime at the time of the most
/// recent change in any instance in the sysORTable.
pub fn sys_or_last_change() -> @oid.Oid {
  lit("1.3.6.1.2.1.1.8.0")
}

///|
/// `interfaces` group root, 1.3.6.1.2.1.2 (RFC 1213 §6.2).
pub fn interfaces() -> @oid.Oid {
  lit("1.3.6.1.2.1.2")
}

///|
/// ifNumber.0 — the number of network interfaces present.
pub fn if_number() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.1.0")
}

///|
/// `ifTable` root, 1.3.6.1.2.1.2.2. `ifIndex` is the table's index, so
/// walking this yields `ifIndex.1`, `ifDescr.1`, ... in column order.
pub fn if_table() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.2")
}

///|
/// `ifEntry` root, 1.3.6.1.2.1.2.2.1. Walking one column under this,
/// such as `if_descr()`, walks that column for every interface.
pub fn if_entry() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.2.1")
}

///|
/// ifDescr column, 1.3.6.1.2.1.2.2.1.2 — a textual string of the
/// interface name, e.g. `eth0`. An OctetString column.
pub fn if_descr() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.2.1.2")
}

///|
/// ifType column, 1.3.6.1.2.1.2.2.1.3 — the interface's physical/link
/// type (an IANAifType integer).
pub fn if_type() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.2.1.3")
}

///|
/// ifMtu column, 1.3.6.1.2.1.2.2.1.4 — the largest datagram the
/// interface can send/receive, in octets.
pub fn if_mtu() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.2.1.4")
}

///|
/// ifSpeed column, 1.3.6.1.2.1.2.2.1.5 — an estimate of the
/// interface's current bandwidth in bits per second (Gauge32).
pub fn if_speed() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.2.1.5")
}

///|
/// ifPhysAddress column, 1.3.6.1.2.1.2.2.1.6 — the interface's address
/// at its protocol sub-layer, usually the MAC (OctetString).
pub fn if_phys_address() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.2.1.6")
}

///|
/// ifOperStatus column, 1.3.6.1.2.1.2.2.1.8 — 1 up, 2 down, 3 testing,
/// ... (RFC 1213 §6.2.9).
pub fn if_oper_status() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.2.1.8")
}

///|
/// ifInOctets column, 1.3.6.1.2.1.2.2.1.10 — total octets received
/// (Counter32, wraps).
pub fn if_in_octets() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.2.1.10")
}

///|
/// ifOutOctets column, 1.3.6.1.2.1.2.2.1.16 — total octets sent
/// (Counter32, wraps).
pub fn if_out_octets() -> @oid.Oid {
  lit("1.3.6.1.2.1.2.2.1.16")
}

///|
/// `ip` group root, 1.3.6.1.2.1.4 (RFC 1213 §6.4).
pub fn ip() -> @oid.Oid {
  lit("1.3.6.1.2.1.4")
}

///|
/// `ipAddrTable` root, 1.3.6.1.2.1.4.20 — the addressing table for
/// this node, indexed by IPv4 address.
pub fn ip_addr_table() -> @oid.Oid {
  lit("1.3.6.1.2.1.4.20")
}

///|
/// `udp` group root, 1.3.6.1.2.1.7 (RFC 1213 §6.6).
pub fn udp() -> @oid.Oid {
  lit("1.3.6.1.2.1.7")
}

///|
/// `tcp` group root, 1.3.6.1.2.1.6 (RFC 1213 §6.5).
pub fn tcp() -> @oid.Oid {
  lit("1.3.6.1.2.1.6")
}

///|
/// `snmp` group root, 1.3.6.1.2.1.11 (RFC 1213 §6.7): counters for the
/// SNMP entity itself.
pub fn snmp() -> @oid.Oid {
  lit("1.3.6.1.2.1.11")
}

///|
/// snmpInPkts.0 — total number of messages delivered to the SNMP
/// entity from the transport service.
pub fn snmp_in_pkts() -> @oid.Oid {
  lit("1.3.6.1.2.1.11.1.0")
}

///|
/// snmpOutPkts.0 — total number of SNMP messages passed from the SNMP
/// protocol entity to the transport service.
pub fn snmp_out_pkts() -> @oid.Oid {
  lit("1.3.6.1.2.1.11.2.0")
}

///|
/// `mib-2` root, 1.3.6.1.2.1 — the second version of the MIB, the
/// parent of system/interfaces/at/ip/icmp/tcp/udp/egp/transmission/snmp.
pub fn mib2() -> @oid.Oid {
  lit("1.3.6.1.2.1")
}
