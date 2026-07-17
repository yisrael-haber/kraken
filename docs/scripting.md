# Kraken Scripting

Kraken scripts are Starlark. Scripts are compiled when saved; invalid scripts remain visible but cannot run or bind.

## Script Kinds

### Transport

Transport scripts use `main(packet, ctx)` and run on outbound and routed traffic for one adopted identity.

- `ctx.scriptName`, `ctx.adopted`, `ctx.metadata`
- `packet.ethernet`, `packet.arp`, `packet.ipv4`, `packet.icmpv4`, `packet.tcp`, `packet.udp` — absent layers are `None`.
- `packet.payload` — bytes payload; assignment requires bytes.
- `packet.copy()`, `packet.create_fragments(mtu)`, `packet.pad_payload(length, byte=0)`, `packet.truncate_payload(length)`
- `packet.send(fix_lengths=True, fix_checksums=True)` — emits the packet. Packets are otherwise dropped.

Transport scripts can load only `kraken/bytes` and `kraken/time`.

Packet fields follow their protocol headers. IPv4 and TCP options are objects with `optionType`, `optionLength`, and `optionData`.

### Global

Global scripts use `main(ctx)` and run manually from the Global scripting view.

- `ctx.scriptName`, `ctx.metadata`
- `ctx.identities["10.0.0.1"]` — an adopted identity selected by IPv4 address.
- Identity fields: `label`, `ip`, `mac`, `interfaceName`, `defaultGateway`, `mtu`.
- `print(...)` streams output to the run view. Stop cancels the script and pending TCP dials.

Global scripts can load `kraken/socket`, `kraken/bytes`, `kraken/time`, `kraken/windows`, and `kraken/dcerpc`.

## Bytes And Time

- `bytes.from_utf8(text)`
- `bytes.concat(a, b, ...)`
- `time.nowMs()`
- `time.sleep(ms)`

Use Starlark byte values such as `b"\x00\xff"` for packet and socket data. Plain strings are not byte values.

## Sockets

```python
load("kraken/socket", "socket")

def main(ctx):
    identity = ctx.identities["10.0.0.1"]
    conn = socket.tcp(identity, "10.0.0.5:445", options={"nodelay": True})
    conn.send(b"...")
    print(conn.recv(4096))
    conn.close()
```

- `socket.tcp(identity, "IPv4:port", options={...})`
- `socket.udp(identity, "IPv4:port", options={...})`
- Connection methods: `send(bytes)`, `recv(size)`, `close()`, `set_option(name, value)`, `local_addr`, `remote_addr`.
- Options: `ttl` (`0..255`), `nodelay` (TCP), `keepalive` (TCP), `reuseaddr`, `recv_buffer`, and `send_buffer`.

Sockets are always opened through the selected adopted identity.

## Windows Helpers

Load with `load("kraken/windows", "windows")`.

- `windows.sid.parse(value)` parses SID text or bytes.
- `windows.security.parse_descriptor(bytes)`, `parse_acl(bytes)`, and `parse_ace(bytes)` parse Windows security structures.
- `windows.security.access_mask_text(mask)` names access-mask flags.
- `windows.ntlm.client(user="", password="", domain="", workstation="", hash="", target_spn="")` creates an NTLM byte generator with `negotiate()` and `authenticate(challenge)`.
- `windows.tds` builds and parses TDS packets and pre-login payloads.
- `windows.utf16le.encode(text)` and `decode(bytes)` convert UTF-16LE.

## DCE/RPC

Load with `load("kraken/dcerpc", "dcerpc")`. DCE/RPC uses an already-open TCP socket; ownership moves to the RPC client.

```python
load("kraken/socket", "socket")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
    conn = socket.tcp(ctx.identities["10.0.0.1"], "10.0.0.5:135")
    rpc = dcerpc.tcp(conn)
    rpc.bind("12345678-1234-5678-90ab-cdef01234567")
    print(rpc.call(0, b""))
    rpc.close()
```

- `dcerpc.tcp(connection)`, `dcerpc.uuid(text)`
- `client.bind(uuid, major=1, minor=0)`, `client.call(opnum, payload=b"")`, `client.close()`
- `client.bind_auth(uuid, auth, major=1, minor=0)` and `client.call_auth(opnum, payload=b"")` use an auth value from `windows.ntlm.client(...)`.
- `client.epm_lookup()` and `client.epm_find(uuid, major=None)` return endpoint data. Open any selected endpoint socket explicitly with `socket.tcp`.

TCP DCE/RPC is available. SMB named-pipe and Kerberos transports are not.
