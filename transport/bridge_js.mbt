///|
/// JavaScript UDP bridge.
///
/// Each open socket gets a worker thread that owns its `node:dgram`
/// socket, plus its own `SharedArrayBuffer`. The main (MoonBit) thread
/// and the worker share that buffer:
///
///   offset 0     control Int32[8]:
///                  [0] state   0 the reader may block, 1 data waiting,
///                              -1 fatal error
///                  [1] local port
///                  [2] head    the slot the reader takes next
///                  [3] tail    the slot the worker fills next
///                  [4] count   slots currently holding a datagram
///                  [5] capacity (the number of slots)
///                  [6] dropped datagrams, because they did not fit or
///                      arrived with the ring already full
///                  [7] sends handed to the worker but not yet completed,
///                      so `close` can wait for them
///   offset 32    the ring: 32 slots of 2128 bytes each
///
/// A slot is laid out as
///
///   + 0    Int32 payload length
///   + 4    Int32 sender port
///   + 8    Int32 sender address length
///   + 12   (padding, so the address starts on a 16-byte boundary)
///   + 16   sender address text, up to 64 bytes
///   + 80   payload, up to 2048 bytes
///
/// All waits use `Atomics.wait`, which blocks the calling thread without
/// spinning and is what makes a synchronous `recv(timeout)` possible.
///
/// Two properties this layout exists to preserve, both learned the hard
/// way:
///
///   * **A send never travels through shared memory.** The payload is
///     copied into the worker's message instead. When it went through
///     the shared buffer, two sends in quick succession raced: the
///     second write clobbered the first before the worker had read it,
///     so the receiver saw a duplicate of the second datagram where the
///     first should have been.
///   * **Received datagrams queue up.** The ring holds 32 of them, so a
///     burst arriving while the reader is busy decoding is not thrown
///     away. A receiver that loses traps is not a receiver; the
///     single-slot mailbox this replaced dropped all but the first of a
///     burst.
///
/// The ring is single-producer (the worker) and single-consumer (the
/// reader). The worker writes a slot and only then increments `count`
/// with an atomic op; the reader reads `count` first, so a slot is
/// never observed half-written.

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
/// client wants; a receiver passes the port it should listen on.
extern "js" fn js_udp_open(bind_port : Int) -> Int =
  #| function(bind_port) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return -1;
  #|  const { Worker } = process.getBuiltinModule("node:worker_threads");
  #|  const workerCode = `
  #|    const { workerData } = process.getBuiltinModule("node:worker_threads");
  #|    const dgram = process.getBuiltinModule("node:dgram");
  #|    const sab = workerData.sab;
  #|    const ctrl = new Int32Array(sab, 0, 8);
  #|    const STRIDE = 2128;
  #|    const CAP = 32;
  #|    const AUX = new Int32Array(sab, 32, CAP * (STRIDE / 4));
  #|    const RAW = new Uint8Array(sab, 32, CAP * STRIDE);
  #|    const encoder = new TextEncoder();
  #|    const sock = dgram.createSocket("udp4");
  #|    let tail = 0;
  #|    function fail(msg) {
  #|      console.error("[snmp-udp] " + msg);
  #|      Atomics.store(ctrl, 0, -1);
  #|      Atomics.notify(ctrl, 0);
  #|    }
  #|    // Decrements the in-flight count the sender incremented, so a
  #|    // close can tell when the last datagram has actually gone out.
  #|    function settle() {
  #|      Atomics.sub(ctrl, 7, 1);
  #|      Atomics.notify(ctrl, 7);
  #|    }
  #|    sock.on("error", (e) => fail("socket error: " + e.message));
  #|    sock.on("message", (msg, rinfo) => {
  #|      const addr = encoder.encode(rinfo.address);
  #|      // Anything that does not fit is counted and dropped: a
  #|      // truncated PDU would decode into a lie.
  #|      if (msg.length > 2048 || addr.length > 64) {
  #|        Atomics.add(ctrl, 6, 1);
  #|        return;
  #|      }
  #|      // A full ring drops the newest datagram. It is counted, so the
  #|      // reader can tell "quiet" from "overwhelmed".
  #|      if (Atomics.load(ctrl, 4) >= CAP) {
  #|        Atomics.add(ctrl, 6, 1);
  #|        return;
  #|      }
  #|      const base = tail * STRIDE;
  #|      RAW.set(addr, base + 16);
  #|      RAW.set(msg, base + 80);
  #|      Atomics.store(AUX, tail * (STRIDE / 4) + 0, msg.length);
  #|      Atomics.store(AUX, tail * (STRIDE / 4) + 1, rinfo.port);
  #|      Atomics.store(AUX, tail * (STRIDE / 4) + 2, addr.length);
  #|      tail = (tail + 1) % CAP;
  #|      Atomics.store(ctrl, 3, tail);
  #|      // Publish only after the slot is complete.
  #|      Atomics.add(ctrl, 4, 1);
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
  #|        // The worker owns its own copy of the bytes: the structured
  #|        // clone in postMessage made it, so the caller may overwrite
  #|        // its buffer as soon as this returns.
  #|        sock.send(cmd.payload, cmd.port, cmd.host, (err) => {
  #|          if (err) fail("send failed: " + err.message);
  #|          settle();
  #|        });
  #|      } else if (cmd.kind === "close") {
  #|        // A send is asynchronous, so a program that closes the socket
  #|        // and exits would otherwise drop the datagram it just handed
  #|        // over. Wait for the last one to go out, but not forever: a
  #|        // peer that has gone away must not wedge the close.
  #|        const deadline = Date.now() + 500;
  #|        while (Atomics.load(ctrl, 7) > 0 && Date.now() < deadline) {
  #|          Atomics.wait(ctrl, 7, Atomics.load(ctrl, 7), 20);
  #|        }
  #|        try { sock.close(); } catch (e) {}
  #|        process.exit(0);
  #|      }
  #|    });
  #|    Atomics.store(ctrl, 2, 0);
  #|    Atomics.store(ctrl, 3, 0);
  #|    Atomics.store(ctrl, 5, CAP);
  #|    sock.bind(workerData.port, "0.0.0.0");
  #|  `;
  #|  const sab = new SharedArrayBuffer(131072);
  #|  const worker = new Worker(workerCode, {
  #|    eval: true,
  #|    workerData: { sab, port: bind_port },
  #|  });
  #|  const handle = reg.sockets.length;
  #|  reg.sockets.push({
  #|    sab,
  #|    ctrl: new Int32Array(sab, 0, 8),
  #|    stride: 2128,
  #|    slots: 32,
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
/// Hand one datagram to the worker to send. Returns the byte count on
/// success or a negative error code.
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
  #|  // Copy the bytes out of the caller's buffer and let the structured
  #|  // clone carry them. This is what makes back-to-back sends safe.
  #|  const copy = Uint8Array.prototype.slice.call(payload);
  #|  // Counted before the post, so a close that follows the post always
  #|  // finds the send accounted for.
  #|  Atomics.add(b.ctrl, 7, 1);
  #|  b.worker.postMessage({ kind: "send", payload: copy, host, port });
  #|  return payload.length;
  #| }

///|
/// Block until a datagram is available or `ms` elapses.
/// Returns 1 when one is waiting, 0 on timeout, -1 on error.
extern "js" fn js_udp_recv(handle : Int, ms : Int) -> Int =
  #| function(handle, ms) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return -1;
  #|  const b = reg.sockets[handle];
  #|  if (!b) return -1;
  #|  // Check for queued data before blocking: the worker may have
  #|  // delivered while the reader was busy.
  #|  if (Atomics.load(b.ctrl, 4) > 0) return 1;
  #|  Atomics.wait(b.ctrl, 0, 0, ms);
  #|  if (Atomics.load(b.ctrl, 0) === -1) return -1;
  #|  if (Atomics.load(b.ctrl, 4) > 0) return 1;
  #|  return 0;
  #| }

///|
/// Copy the datagram at the head of the ring out of the shared buffer
/// and advance the head.
extern "js" fn js_udp_take(handle : Int) -> Bytes =
  #| function(handle) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return new Uint8Array(0);
  #|  const b = reg.sockets[handle];
  #|  if (!b) return new Uint8Array(0);
  #|  if (Atomics.load(b.ctrl, 4) <= 0) return new Uint8Array(0);
  #|  const STRIDE = b.stride;
  #|  const head = Atomics.load(b.ctrl, 2);
  #|  const AUX = new Int32Array(b.sab, 32, b.slots * (STRIDE / 4));
  #|  const len = Atomics.load(AUX, head * (STRIDE / 4) + 0);
  #|  const out = new Uint8Array(len);
  #|  out.set(new Uint8Array(b.sab, 32 + head * STRIDE + 80, len), 0);
  #|  Atomics.store(b.ctrl, 2, (head + 1) % b.slots);
  #|  Atomics.sub(b.ctrl, 4, 1);
  #|  // Back to idle once drained, so the next wait blocks properly.
  #|  if (Atomics.load(b.ctrl, 4) === 0) Atomics.store(b.ctrl, 0, 0);
  #|  return out;
  #| }

///|
/// The sender port of the datagram waiting at the head of the ring.
extern "js" fn js_udp_from_port(handle : Int) -> Int =
  #| function(handle) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return 0;
  #|  const b = reg.sockets[handle];
  #|  if (!b) return 0;
  #|  if (Atomics.load(b.ctrl, 4) <= 0) return 0;
  #|  const STRIDE = b.stride;
  #|  const AUX = new Int32Array(b.sab, 32, b.slots * (STRIDE / 4));
  #|  return Atomics.load(AUX, Atomics.load(b.ctrl, 2) * (STRIDE / 4) + 1);
  #| }

///|
/// The sender address of the datagram waiting at the head of the ring.
///
/// Read this before `js_udp_take`: taking advances the head, so a read
/// afterwards would describe the next datagram instead.
extern "js" fn js_udp_from_addr(handle : Int) -> String =
  #| function(handle) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return "";
  #|  const b = reg.sockets[handle];
  #|  if (!b) return "";
  #|  if (Atomics.load(b.ctrl, 4) <= 0) return "";
  #|  const STRIDE = b.stride;
  #|  const head = Atomics.load(b.ctrl, 2);
  #|  const AUX = new Int32Array(b.sab, 32, b.slots * (STRIDE / 4));
  #|  const len = Atomics.load(AUX, head * (STRIDE / 4) + 2);
  #|  if (len <= 0 || len > 64) return "";
  #|  const bytes = new Uint8Array(b.sab, 32 + head * STRIDE + 16, len);
  #|  let out = "";
  #|  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  #|  return out;
  #| }

///|
/// How many datagrams this socket has dropped, because they were larger
/// than a slot or arrived with the ring already full.
extern "js" fn js_udp_dropped(handle : Int) -> Int =
  #| function(handle) {
  #|  const reg = globalThis.__snmpUdp;
  #|  if (!reg) return 0;
  #|  const b = reg.sockets[handle];
  #|  return b ? Atomics.load(b.ctrl, 6) : 0;
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
  #|  // Give the worker a moment to flush what it is still sending; it
  #|  // exits by itself once it has. Terminating straight away, as this
  #|  // once did, silently dropped the last datagram.
  #|  const deadline = Date.now() + 600;
  #|  while (Atomics.load(b.ctrl, 7) > 0 && Date.now() < deadline) {
  #|    Atomics.wait(b.ctrl, 7, Atomics.load(b.ctrl, 7), 20);
  #|  }
  #|  try { b.worker.terminate(); } catch (e) {}
  #|  b.closed = true;
  #| }
