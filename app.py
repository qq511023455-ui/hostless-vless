#!/usr/bin/env python3
"""
VLESS server (pure stdlib, asyncio) for Hostless free App tier.
- Hostless Apps are served over HTTPS only (*.hostless.app, port 443).
  Raw TCP VLESS cannot pass the HTTPS proxy, so VLESS runs over
  WebSocket (path /vless) with TLS terminated by Hostless.
- Listens on 0.0.0.0:$PORT (Hostless sets PORT, default 8000).
  Also honours $SERVER_PORT as a fallback.
- GET / returns 200 "ok" (HTTP health check).
- VLESS UUID comes from $VLESS_UUID only. It is NOT in this repo.
  If unset, a random UUID is generated at startup and printed to logs.
- Protocol: VLESS, security=none, TCP + UDP, over WebSocket.
- Client link: vless://<UUID>@<app>.hostless.app:443?path=%2Fvless&type=ws&security=tls&sni=<app>.hostless.app#Hostless
- No third-party dependencies.
"""
import asyncio
import base64
import hashlib
import os
import socket
import struct
import sys
import uuid

VLESS_UUID = os.environ.get("VLESS_UUID", "").strip()
if VLESS_UUID:
    try:
        UUID_BYTES = uuid.UUID(VLESS_UUID).bytes
    except Exception:
        VLESS_UUID = ""
        UUID_BYTES = uuid.uuid4().bytes
        VLESS_UUID = str(uuid.UUID(bytes=UUID_BYTES))
else:
    UUID_BYTES = uuid.uuid4().bytes
    VLESS_UUID = str(uuid.UUID(bytes=UUID_BYTES))

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "") or os.environ.get("SERVER_PORT", "") or 8000)
WS_PATH = os.environ.get("WS_PATH", "/vless")

CMD_TCP = 1
CMD_UDP = 2
CMD_MUX = 3
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def log(*a):
    print(*a, flush=True)


# ---------------------------------------------------------------- WebSocket --
class WSStream:
    """Byte-stream view over one WebSocket connection.

    Presents the readexactly/read/write/drain/close interface used by the
    VLESS handlers, reassembling WS binary frames into a plain byte stream.
    """

    def __init__(self, reader, writer, peer):
        self._r = reader
        self._w = writer
        self._peer = peer
        self._buf = bytearray()
        self._eof = False

    def get_extra_info(self, name):
        if name == "peername":
            return self._peer
        return None

    async def _fill(self):
        """Read one WS frame; append binary payload to buffer."""
        if self._eof:
            return False
        try:
            head = await self._r.readexactly(2)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            self._eof = True
            return False
        fin = head[0] & 0x80
        opcode = head[0] & 0x0F
        masked = head[1] & 0x80
        ln = head[1] & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", await self._r.readexactly(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", await self._r.readexactly(8))[0]
        mask = await self._r.readexactly(4) if masked else None
        payload = await self._r.readexactly(ln) if ln else b""
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if opcode == 0x9:  # ping -> pong
            self._send_frame(0xA, payload)
            await self._w.drain()
            return await self._fill()
        if opcode == 0x8:  # close
            self._eof = True
            return False
        if opcode in (0x2, 0x0, 0x1):  # binary / continuation / text
            self._buf += payload
            return True
        # unknown opcode: ignore frame
        return await self._fill()

    def _send_frame(self, opcode, payload):
        header = bytes([0x80 | opcode])
        ln = len(payload)
        if ln < 126:
            header += bytes([ln])
        elif ln < 65536:
            header += bytes([126]) + struct.pack(">H", ln)
        else:
            header += bytes([127]) + struct.pack(">Q", ln)
        self._w.write(header + payload)

    async def read(self, n=-1):
        while not self._buf and not self._eof:
            if not await self._fill():
                break
        if not self._buf:
            return b""
        if n is None or n < 0 or n >= len(self._buf):
            data = bytes(self._buf)
            self._buf.clear()
            return data
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    async def readexactly(self, n):
        while len(self._buf) < n and not self._eof:
            if not await self._fill():
                break
        if len(self._buf) < n:
            raise asyncio.IncompleteReadError(bytes(self._buf), n)
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    def write(self, data):
        if not data:
            return
        # Split into 32 KiB frames so a large relay chunk is not one huge frame.
        for i in range(0, len(data), 32768):
            self._send_frame(0x2, data[i:i + 32768])

    async def drain(self):
        await self._w.drain()

    def close(self):
        try:
            self._w.close()
        except Exception:
            pass


# ------------------------------------------------------------------- VLESS --
async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log("pipe error:", e)
    finally:
        try:
            writer.close()
        except Exception:
            pass


def parse_address(buf, off):
    if off + 1 > len(buf):
        return None
    atype = buf[off]
    off += 1
    if atype == 1:
        if off + 4 + 2 > len(buf):
            return None
        addr = socket.inet_ntoa(buf[off:off + 4])
        off += 4
    elif atype == 3:
        if off + 16 + 2 > len(buf):
            return None
        addr = socket.inet_ntop(socket.AF_INET6, buf[off:off + 16])
        off += 16
    elif atype == 2:
        if off + 1 > len(buf):
            return None
        n = buf[off]
        off += 1
        if off + n + 2 > len(buf):
            return None
        addr = buf[off:off + n].decode("utf-8", "ignore")
        off += n
    else:
        return None
    port = struct.unpack(">H", buf[off:off + 2])[0]
    off += 2
    return atype, addr, port, off


async def handle_tcp_target(reader, writer, addr, port, first_payload):
    try:
        r, w = await asyncio.open_connection(addr, port)
    except Exception as e:
        log(f"TCP connect {addr}:{port} failed: {e}")
        writer.close()
        return
    log(f"TCP -> {addr}:{port}")
    if first_payload:
        w.write(first_payload)
        await w.drain()
    t1 = asyncio.create_task(pipe(reader, w))
    t2 = asyncio.create_task(pipe(r, writer))
    await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
    for t in (t1, t2):
        t.cancel()
    try:
        w.close()
    except Exception:
        pass


async def handle_udp(reader, writer):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setblocking(False)
    udp_sock.bind(("0.0.0.0", 0))
    loop = asyncio.get_running_loop()
    log("UDP session started")

    async def udp_recv_loop():
        while True:
            try:
                data, _src = await loop.sock_recvfrom(udp_sock, 65536)
            except (asyncio.CancelledError, OSError):
                break
            try:
                hdr = getattr(udp_recv_loop, "last_hdr", b"\x01\x00\x00\x00\x00\x00\x00")
                pkt = hdr + data
                writer.write(struct.pack(">H", len(pkt)) + pkt)
                await writer.drain()
            except Exception:
                break

    recv_task = asyncio.create_task(udp_recv_loop())
    try:
        while True:
            hdr2 = await reader.readexactly(2)
            pkt_len = struct.unpack(">H", hdr2)[0]
            pkt = await reader.readexactly(pkt_len)
            if len(pkt) < 3:
                continue
            port = struct.unpack(">H", pkt[0:2])[0]
            atype = pkt[2]
            if atype == 1 and len(pkt) >= 2 + 1 + 4:
                addr = socket.inet_ntoa(pkt[3:7])
                payload = pkt[7:]
            elif atype == 2 and len(pkt) >= 4:
                n = pkt[3]
                addr = pkt[4:4 + n].decode("utf-8", "ignore")
                payload = pkt[4 + n:]
            elif atype == 3 and len(pkt) >= 2 + 1 + 16:
                addr = socket.inet_ntop(socket.AF_INET6, pkt[3:19])
                payload = pkt[19:]
            else:
                continue
            if atype == 1:
                udp_recv_loop.last_hdr = struct.pack(">H", port) + bytes([1]) + socket.inet_aton(addr)
            elif atype == 2:
                b = addr.encode()
                udp_recv_loop.last_hdr = struct.pack(">H", port) + bytes([2, len(b)]) + b
            else:
                udp_recv_loop.last_hdr = struct.pack(">H", port) + bytes([3]) + socket.inet_pton(socket.AF_INET6, addr)
            try:
                await loop.sock_sendto(udp_sock, payload, (addr, port))
            except Exception as e:
                log(f"UDP send {addr}:{port} failed: {e}")
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log("UDP session error:", e)
    finally:
        recv_task.cancel()
        try:
            udp_sock.close()
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass


async def handle_client(stream, peer):
    reader = stream
    writer = stream
    try:
        head = await reader.readexactly(18)
        version = head[0]
        cli_uuid = head[1:17]
        addon_len = head[17]
        if cli_uuid != UUID_BYTES:
            log(f"bad uuid from {peer}")
            writer.close()
            return
        if addon_len:
            await reader.readexactly(addon_len)
        cmd_port = await reader.readexactly(3)
        cmd = cmd_port[0]
        port = struct.unpack(">H", cmd_port[1:3])[0]
        atype_b = await reader.readexactly(1)
        atype = atype_b[0]
        if atype == 1:
            addr_b = await reader.readexactly(4)
            addr = socket.inet_ntoa(addr_b)
        elif atype == 3:
            addr_b = await reader.readexactly(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr_b)
        elif atype == 2:
            n_b = await reader.readexactly(1)
            n = n_b[0]
            addr = (await reader.readexactly(n)).decode("utf-8", "ignore")
        else:
            writer.close()
            return
        writer.write(bytes([version, 0]))
        await writer.drain()
        if cmd == CMD_TCP:
            await handle_tcp_target(reader, writer, addr, port, b"")
        elif cmd == CMD_UDP:
            await handle_udp(reader, writer)
        else:
            log(f"unsupported command {cmd} from {peer}")
            writer.close()
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log(f"client {peer} error: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


# -------------------------------------------------------------------- HTTP ---
async def handle_http(reader, writer):
    peer = writer.get_extra_info("peername")
    try:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, asyncio.TimeoutError):
            writer.close()
            return
        try:
            head = raw.decode("iso-8859-1")
        except Exception:
            writer.close()
            return
        lines = head.split("\r\n")
        method, path = "", "/"
        if lines and lines[0]:
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                method, path = parts[0], parts[1]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        upgrade = headers.get("upgrade", "").lower()
        key = headers.get("sec-websocket-key", "")
        if upgrade == "websocket" and key:
            accept = base64.b64encode(
                hashlib.sha1((key + WS_GUID).encode()).digest()
            ).decode()
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            writer.write(resp.encode())
            await writer.drain()
            stream = WSStream(reader, writer, peer)
            await handle_client(stream, peer)
            return
        if method == "GET" and path in ("/", "/health", "/healthz"):
            body = b"ok\n"
            resp = (
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode() + body
            writer.write(resp)
            await writer.drain()
            writer.close()
            return
        body = b"not found\n"
        resp = (
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode() + body
        writer.write(resp)
        await writer.drain()
        writer.close()
    except Exception as e:
        log(f"http {peer} error: {e}")
        try:
            writer.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle_http, HOST, PORT)
    log(f"VLESS-WS server listening on {HOST}:{PORT} path={WS_PATH} uuid={VLESS_UUID}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
