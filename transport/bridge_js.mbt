///|
/// JavaScript UDP bridge.
///
/// Each open socket gets a worker thread that owns its `node:dgram`
/// socket, plus its own `SharedArrayBuffer`. The main (MoonBit) thread
/// and the worker share that buffer:
///
///   offset 0    control Int32[4]:
///                 [0] state: 0 idle, 1 packet ready, 2 binding, -1 error
///                 [1] local port
///                 [2] received byte count
///                 [3] sender port
///   offset 16   incoming packet bytes (2048)
///   offset 2064 outgoing packet bytes (2048)
///   offset 4112 the sender address: byte length at 4112..4115 (an
///               Int32), then up to 252 bytes of text. A trap receiver
///               needs this: who sent a notification is most of what a
///               notification means.
///   total 8192
///
/// All waits use `Atomics.wait`, which blocks the calling thread without
/// spinning and is what makes a synchronous `recv(timeout)` possible.
///
/// The mailbox holds one packet. The worker refuses to overwrite a
/// packet that has not been consumed yet, so the payload and the sender
/// address a reader sees always belong to the same datagram; under
/// overload a packet is dropped rather than tearing a pair apart.
///
/// Sockets are addressed by a small integer handle, because a process
/// legitimately wants more than one: a client querying an agent while a
/// receiver listens for the agent's traps needs two.

///|
/// Install the socket registry if this is the first open.
///
/// The registry holds one context per open socket. A handle is the
/// index into it, and 0 is a valid handle, so -1 is the error value
/// everywhere a handle is returned.
extern "js" fn js_udp_registry() -> Unit =
  #| function() {
  #|  if (!globalThis.__snmpUdp) globalThis.__snmpUdp = { sockets: [] };
  #| }

///|
/// Open a socket and return its handle, or -1 on error.
///
/// `bind_port` of 0 asks the OS for an ephemeral port, which is what a
/// client wants; a receiver passes the port it is expected to listen
/// on.
extern "js" fn js_udp_open(bind_port : Int) -> Int =
  #| function(bind_port) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return -1;
  #|  const { Worker } = process.getBuiltinModule("node:worker_threads");
  #|  const workerCode = `
  #|    const { workerData } = process.getBuiltinModule("node:worker_threads");
  #|    const dgram = process.getBuiltinModule("node:dgram");
  #|    const sab = workerData.sab;
  #|    const ctrl = new Int32Array(sab, 0, 4);
  #|    const inView = new Uint8Array(sab, 16, 2048);
  #|    const outView = new Uint8Array(sab, 2064, 2048);
  #|    const addrLen = new Int32Array(sab, 4112, 1);
  #|    const addrView = new Uint8Array(sab, 4116, 252);
  #|    const encoder = new TextEncoder();
  #|    const sock = dgram.createSocket("udp4");
  #|    function fail(msg) {
  #|      console.error("[snmp-udp] " + msg);
  #|      Atomics.store(ctrl, 0, -1);
  #|      Atomics.notify(ctrl, 0);
  #|    }
  #|    sock.on("error", (e) => fail("socket error: " + e.message));
  #|    sock.on("message", (msg, rinfo) => {
  #|      // Drop anything that will not fit rather than truncate a PDU.
  #|      if (msg.length > inView.length) return;
  #|      // Do not overwrite a packet the reader has not taken yet: that
  #|      // would pair one datagram's payload with another's address.
  #|      if (Atomics.load(ctrl, 0) === 1) return;
  #|      const addr = encoder.encode(rinfo.address);
  #|      if (addr.length > addrView.length) return;
  #|      addrView.set(addr, 0);
  #|      Atomics.store(addrLen, 0, addr.length);
  #|      inView.set(msg, 0);
  #|      Atomics.store(ctrl, 2, msg.length);
  #|      Atomics.store(ctrl, 3, rinfo.port);
  #|      Atomics.store(ctrl, 0, 1);
  #|      Atomics.notify(ctrl, 0);
  #|    });
  #|    sock.on("listening", () => {
  #|      Atomics.store(ctrl, 1, sock.address().port);
  #|      Atomics.store(ctrl, 0, 0);
  #|      Atomics.notify(ctrl, 0);
  #|    });
  #|    const { parentPort } = process.getBuiltinModule("node:worker_threads");
  #|    parentPort.on("message", (cmd) => {
  #|      if (cmd.kind === "send") {
  #|        const payload = Buffer.from(outView.slice(0, cmd.len));
  #|        sock.send(payload, cmd.port, cmd.host, (err) => {
  #|          if (err) fail("send failed: " + err.message);
  #|        });
  #|      } else if (cmd.kind === "close") {
  #|        try { sock.close(); } catch (e) {}
  #|        process.exit(0);
  #|      }
  #|    });
  #|    sock.bind(workerData.port, "0.0.0.0");
  #|  `;
  #|  const sab = new SharedArrayBuffer(8192);
  #|  const worker = new Worker(workerCode, {
  #|    eval: true,
  #|    workerData: { sab, port: bind_port },
  #|  });
  #|  const handle = reg.sockets.length;
  #|  reg.sockets.push({
  #|    sab,
  #|    ctrl: new Int32Array(sab, 0, 4),
  #|    worker,
  #|    closed: false,
  #|  });
  #|  return handle;
  #| }

///|
/// Wait for the socket to finish binding, up to `ms` ms.
/// Returns the bound port, or -1 on error, or 0 on timeout.
extern "js" fn js_udp_wait_bound(handle : Int, ms : Int) -> Int =
  #| function(handle, ms) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return -1;
  #|  const b = reg.sockets[handle];
  #|  if (!b) return -1;
  #|  // The worker sets state 0 (idle) and the port once listening.
  #|  const start = Date.now();
  #|  while (Atomics.load(b.ctrl, 1) === 0) {
  #|    const left = ms - (Date.now() - start);
  #|    if (left <= 0) return 0;
  #|    Atomics.wait(b.ctrl, 0, -2, Math.min(left, 50));
  #|    if (Atomics.load(b.ctrl, 0) === -1) return -1;
  #|  }
  #|  return Atomics.load(b.ctrl, 1);
  #| }

///|
/// Copy `payload` into this socket's outgoing block and ask its worker
/// to send it to `host:port`. Returns the byte count handed to the OS,
/// or a negative error code.
///
/// `host` may be a name or a dotted-decimal address: node's `dgram.send`
/// resolves names itself, so no separate lookup is needed.
extern "js" fn js_udp_send(
  handle : Int,
  payload : Bytes,
  host : String,
  port : Int,
) -> Int =
  #| function(handle, payload, host, port) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return -1;
  #|  const b = reg.sockets[handle];
  #|  if (!b || b.closed) return -1;
  #|  // A MoonBit Bytes is a Uint8Array on this backend, so it is copied
  #|  // straight into the shared outgoing block.
  #|  if (payload.length > 2048) return -2;
  #|  new Uint8Array(b.sab, 2064, 2048).set(payload, 0);
  #|  b.worker.postMessage({ kind: "send", len: payload.length, host, port });
  #|  return payload.length;
  #| }

///|
/// Block until a packet arrives or `ms` elapses. Returns the byte count,
/// 0 on timeout, or -1 on error.
extern "js" fn js_udp_recv(handle : Int, ms : Int) -> Int =
  #| function(handle, ms) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return -1;
  #|  const b = reg.sockets[handle];
  #|  if (!b) return -1;
  #|  // A packet may already be waiting from a previous call.
  #|  if (Atomics.load(b.ctrl, 0) === 1) return Atomics.load(b.ctrl, 2);
  #|  Atomics.wait(b.ctrl, 0, 0, ms);
  #|  if (Atomics.load(b.ctrl, 0) === 1) return Atomics.load(b.ctrl, 2);
  #|  if (Atomics.load(b.ctrl, 0) === -1) return -1;
  #|  return 0;
  #| }

///|
/// Copy the received packet out of the shared buffer.
extern "js" fn js_udp_take(handle : Int) -> Bytes =
  #| function(handle) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return new Uint8Array(0);
  #|  const b = reg.sockets[handle];
  #|  if (!b) return new Uint8Array(0);
  #|  const len = Atomics.load(b.ctrl, 2);
  #|  const out = new Uint8Array(len);
  #|  out.set(new Uint8Array(b.sab, 16, len), 0);
  #|  // Mark the slot free so the next recv blocks again.
  #|  Atomics.store(b.ctrl, 0, 0);
  #|  Atomics.store(b.ctrl, 2, 0);
  #|  return out;
  #| }

///|
/// The sender port of the most recent packet.
extern "js" fn js_udp_from_port(handle : Int) -> Int =
  #| function(handle) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return 0;
  #|  const b = reg.sockets[handle];
  #|  return b ? Atomics.load(b.ctrl, 3) : 0;
  #| }

///|
/// The sender address of the most recent packet, as text. Empty when
/// the address was not recorded.
///
/// Read this before `js_udp_take`, which frees the slot: reading after
/// would race with the next arriving packet.
extern "js" fn js_udp_from_addr(handle : Int) -> String =
  #| function(handle) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return "";
  #|  const b = reg.sockets[handle];
  #|  if (!b) return "";
  #|  const len = Atomics.load(new Int32Array(b.sab, 4112, 1), 0);
  #|  if (len <= 0 || len > 252) return "";
  #|  const bytes = new Uint8Array(b.sab, 4116, len);
  #|  let out = "";
  #|  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  #|  return out;
  #| }

///|
/// Stop this socket's worker and release it. Safe to call more than
/// once; a closed handle is left in the registry as a tombstone so
/// handles stay stable.
extern "js" fn js_udp_close(handle : Int) -> Unit =
  #| function(handle) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return;
  #|  const b = reg.sockets[handle];
  #|  if (!b || b.closed) return;
  #|  try { b.worker.postMessage({ kind: "close" }); } catch (e) {}
  #|  try { b.worker.terminate(); } catch (e) {}
  #|  b.closed = true;
  #| }
