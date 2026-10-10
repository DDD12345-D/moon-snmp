///|
/// JavaScript UDP bridge.
///
/// A worker thread owns the `node:dgram` socket. The main (MoonBit)
/// thread and the worker share one `SharedArrayBuffer`:
///
///   offset 0    control Int32[4]:
///                 [0] state: 0 idle, 1 packet ready, -1 error
///                 [1] local port
///                 [2] received byte count
///                 [3] sender port
///   offset 16   incoming packet bytes
///   offset 2064 outgoing packet bytes (written before a send)
///   offset 4112 the send command: byte length at [0..3] (Int32),
///               "host:port" text after, so the worker knows where to
///               send
///
/// All waits use `Atomics.wait`, which blocks the calling thread without
/// spinning and is what makes a synchronous `recv(timeout)` possible.

///|
/// The control block layout, in one place so both sides agree.
const CTRL_STATE : Int = 0

///|
const CTRL_PORT : Int = 1

///|
const CTRL_LEN : Int = 2

///|
const CTRL_FROM_PORT : Int = 3

///|
/// Byte offsets inside the shared buffer.
const OFF_CTRL : Int = 0

///|
const OFF_IN : Int = 16

///|
const OFF_OUT : Int = 2064

///|
/// Address text is copied here, right after the outgoing payload block.
const OFF_ADDR : Int = 4112

///|
const OUT_CAP : Int = 2048

///|
const ADDR_CAP : Int = 256

///|
const SAB_SIZE : Int = 8192

///|
/// Open the socket and start the worker. `bind_port` of 0 asks the OS
/// for an ephemeral port, which is what a manager wants.
extern "js" fn js_udp_open(bind_port : Int) -> Unit =
  #| function(bind_port) {
  #|  if (globalThis.__snmpUdp && !globalThis.__snmpUdp.closed) return;
  #|  const { Worker } = process.getBuiltinModule("node:worker_threads");
  #|  const workerCode = `
  #|    const { workerData } = process.getBuiltinModule("node:worker_threads");
  #|    const dgram = process.getBuiltinModule("node:dgram");
  #|    const sab = workerData.sab;
  #|    const ctrl = new Int32Array(sab, 0, 4);
  #|    const inView = new Uint8Array(sab, 16, 2048);
  #|    const outView = new Uint8Array(sab, 2064, 2048);
  #|    const addrView = new Uint8Array(sab, 4112, 256);
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
  #|    // The main thread posts {host, port} here to request a send.
  #|    parentPort.on("message", (cmd) => {
  #|      if (cmd.kind === "send") {
  #|        const len = cmd.len;
  #|        const payload = Buffer.from(outView.slice(0, len));
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
  #|  globalThis.__snmpUdp = {
  #|    sab,
  #|    ctrl: new Int32Array(sab, 0, 4),
  #|    worker,
  #|    closed: false,
  #|  };
  #| }

///|
/// Wait for the socket to finish binding, up to `ms` ms.
/// Returns the bound port, or -1 on error, or 0 on timeout.
extern "js" fn js_udp_wait_bound(ms : Int) -> Int =
  #| function(ms) {
  #|  const b = globalThis.__snmpUdp;
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
/// Copy `payload` into the outgoing block and ask the worker to send it
/// to `host:port`. Returns the byte count handed to the OS, or a
/// negative error code.
///
/// `host` may be a name or a dotted-decimal address: node's `dgram.send`
/// resolves names itself, so no separate lookup is needed.
extern "js" fn js_udp_send(payload : Bytes, host : String, port : Int) -> Int =
  #| function(payload, host, port) {
  #|  const b = globalThis.__snmpUdp;
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
extern "js" fn js_udp_recv(ms : Int) -> Int =
  #| function(ms) {
  #|  const b = globalThis.__snmpUdp;
  #|  if (!b) return -1;
  #|  // A packet may already be waiting from a previous call.
  #|  if (Atomics.load(b.ctrl, 0) === 1) return Atomics.load(b.ctrl, 2);
  #|  const r = Atomics.wait(b.ctrl, 0, 0, ms);
  #|  if (Atomics.load(b.ctrl, 0) === 1) return Atomics.load(b.ctrl, 2);
  #|  if (Atomics.load(b.ctrl, 0) === -1) return -1;
  #|  return 0;
  #| }

///|
/// Copy the received packet out of the shared buffer.
extern "js" fn js_udp_take() -> Bytes =
  #| function() {
  #|  const b = globalThis.__snmpUdp;
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
extern "js" fn js_udp_from_port() -> Int =
  #| function() {
  #|  const b = globalThis.__snmpUdp;
  #|  return b ? Atomics.load(b.ctrl, 3) : 0;
  #| }

///|
/// Stop the worker and release the socket.
extern "js" fn js_udp_close() -> Unit =
  #| function() {
  #|  const b = globalThis.__snmpUdp;
  #|  if (!b) return;
  #|  try { b.worker.postMessage({ kind: "close" }); } catch (e) {}
  #|  try { b.worker.terminate(); } catch (e) {}
  #|  b.closed = true;
  #|  globalThis.__snmpUdp = undefined;
  #| }
