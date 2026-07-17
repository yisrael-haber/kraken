# Kraken Scripting

Kraken has two script libraries:

- `Transport scripts`
  Stored in `scripts/Transport/`. They use `main(packet, ctx)` and run on adopted identity packet flow.
- `Global scripts`
  Stored in `scripts/Generic/`. They use `main(ctx)` and run manually from Global scripting. They can use adopted identity sockets, byte helpers, Windows protocol helpers, and DCE/RPC helpers.

Mandiant gopacket integration priorities and constraints are tracked in
[gopacket-integration.md](gopacket-integration.md).

## Global Scripts

Generic socket example:

```python
load("kraken/socket", "socket")

def main(ctx):
    identity = ctx.identities["10.0.0.1"]
    connection = socket.tcp(identity, "10.0.0.5:445", options={
        "ttl": 64,
        "nodelay": True,
        "keepalive": True,
    })
    connection.send(b"...")
    print(connection.recv(4096))
    connection.close()
```

### Context

- `ctx.scriptName`, `ctx.metadata`
  Common run context fields.
- `ctx.identities["10.0.0.1"]`
  Looks up an adopted identity by IP. Missing identities raise a Starlark error.
- Identity fields:
  `label`, `ip`, `mac`, `interfaceName`, `defaultGateway`, `mtu`.
- `print(...)`
  Streams to stdout in the Run tab. Runtime errors stream to stderr.

### Modules

- `load("kraken/socket", "socket")`
- `load("kraken/bytes", "bytes")`
- `load("kraken/time", "time")`
- `load("kraken/windows", "windows")`
- `load("kraken/dcerpc", "dcerpc")`

### Bytes And Time

- `bytes.from_utf8(text)`
  Converts text to bytes.
- `bytes.concat(a, b, ...)`
  Concatenates byte values.
- Starlark byte literals such as `b"\x00\xff"` are supported.
- `time.nowMs()`
  Returns a millisecond timestamp.
- `time.sleep(ms)`
  Sleeps for milliseconds and is canceled when the user presses Stop.

### Sockets

- `socket.tcp(identity, "10.0.0.5:445", options={...})`
  Opens a TCP connection through an adopted identity.
- `socket.udp(identity, "10.0.0.5:53", options={...})`
  Opens a UDP connection through an adopted identity.
- Address strings must be `"IPv4:port"`.
- TCP dials are canceled when the user presses Stop.
- Socket options:
  `ttl` integer `0..255`, `nodelay` bool (TCP only), `keepalive` bool (TCP only), `reuseaddr` bool, `recv_buffer` integer bytes, `send_buffer` integer bytes.
- Connection API:
  `send(bytes)`, `recv(size)`, `close()`, `set_option(name, value)`, `local_addr`, `remote_addr`.
- `set_option(name, value)`
  Accepts the same option names as socket creation options.

## Windows Helpers

Load with:

```python
load("kraken/windows", "windows")
```

### SID

- `windows.sid.parse(value)`
  Parses SID text or binary SID bytes.
- SID fields:
  `text`, `bytes`, `revision`, `authority`, `subAuthorities`.

### Security

- `windows.security.parse_descriptor(bytes)`
  Parses a self-relative security descriptor.
- Security descriptor fields:
  `revision`, `control`, `owner`, `group`, `sacl`, `dacl`, `bytes`.
- `windows.security.parse_acl(bytes)`
  Parses an ACL.
- ACL fields:
  `revision`, `aceCount`, `aces`, `bytes`.
- `windows.security.parse_ace(bytes)`
  Parses one ACE.
- ACE fields:
  `type`, `flags`, `mask`, `maskText`, `sid`, `text`, `bytes`, `consumed`.
- `windows.security.access_mask_text(mask)`
  Converts a Windows access mask integer to named flags.

### NTLM

- `windows.ntlm.client(user="", password="", domain="", workstation="", hash="", target_spn="")`
  Creates an NTLMv2 byte generator.
- `client.negotiate()`
  Returns the NTLM negotiate message bytes.
- `client.authenticate(challenge_bytes)`
  Returns the NTLM authenticate message bytes for a server challenge.
- `hash` accepts an NT hash as 32 hex characters, `LM:NT`, or `:NT`.

### TDS

- Constants:
  `windows.tds.type_prelogin`, `windows.tds.type_login7`, `windows.tds.type_tabular`, `windows.tds.status_eom`.
- `windows.tds.packet(type, data=b"", status=windows.tds.status_eom, spid=0, packet_id=1, window=0)`
  Returns raw TDS packet bytes.
- `windows.tds.parse_packet(bytes)`
  Parses a TDS packet. Fields: `type`, `status`, `length`, `spid`, `packet_id`, `window`, `data`.
- `windows.tds.prelogin(version=b"\x00\x00\x00\x00\x00\x00", encryption=0, instance="", thread_id=0)`
  Returns raw pre-login payload bytes.
- `windows.tds.parse_prelogin(bytes)`
  Parses a pre-login payload. Fields: `version`, `encryption`, `instance`, `thread_id`.

### UTF-16LE

- `windows.utf16le.encode(text)`
  Converts text to UTF-16LE bytes.
- `windows.utf16le.decode(bytes)`
  Converts UTF-16LE bytes to text.

## DCE/RPC

Load with:

```python
load("kraken/dcerpc", "dcerpc")
```

Current DCE/RPC support is TCP bind/call, NTLM-authenticated TCP bind/call, and endpoint mapper lookup. Kerberos RPC, SMB named-pipe transport, high-level service clients, and automatic endpoint dialing are intentionally not exposed yet.

### Client

- `dcerpc.tcp(connection)`
  Wraps an open TCP connection from `socket.tcp(...)` as a DCE/RPC client.
- Socket creation and socket options stay owned by `kraken/socket`.
- Ownership transfers to the DCE/RPC client; close the client, not the original socket connection.
- `client.bind(uuid, major=1, minor=0)`
  Binds to an interface UUID and version.
- `client.call(opnum, payload=b"")`
  Sends a raw DCE/RPC request stub and returns raw response stub bytes.
- `client.bind_auth(uuid, auth, major=1, minor=0)`
  Performs an NTLM-authenticated bind with packet privacy. `auth` must come from `windows.ntlm.client(...)`.
- `client.call_auth(opnum, payload=b"")`
  Sends an authenticated sealed request after `bind_auth(...)`.
- `client.close()`
  Closes the wrapped TCP connection.
- `dcerpc.uuid("12345678-1234-5678-90ab-cdef01234567")`
  Returns DCE/RPC wire-format UUID bytes.

### Endpoint Mapper

- `client.epm_lookup()`
  Binds to endpoint mapper and returns endpoint objects.
- `client.epm_find(uuid, major=None)`
  Returns the first matching endpoint or `None`. It filters endpoint mapper data only; scripts still open sockets through `socket.tcp(...)`.
- Endpoint fields:
  `uuid`, `version`, `major`, `minor`, `annotation`, `protocol`, `provider`, `bindings`, `tcp_bindings`.
- `endpoint.tcp_binding()`
  Returns the first TCP binding object or `None`.
- TCP binding fields:
  `raw`, `protocol`, `host`, `port`, `address`.

Endpoint mapper workflow:

```python
load("kraken/socket", "socket")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
    identity = ctx.identities["10.0.0.1"]

    epm = dcerpc.tcp(socket.tcp(identity, "10.0.0.5:135"))
    endpoint = epm.epm_find(uuid="367ABB81-9844-35F1-AD32-98F038001003", major=2)
    if endpoint == None:
        print("endpoint not found")
        epm.close()
        return

    binding = endpoint.tcp_binding()
    print(binding.address)
    epm.close()

    rpc = dcerpc.tcp(socket.tcp(identity, binding.address))
    rpc.bind(endpoint.uuid, major=endpoint.major, minor=endpoint.minor)
    print(rpc.call(0, b""))
    rpc.close()
```

NTLM-authenticated call shape:

```python
load("kraken/socket", "socket")
load("kraken/windows", "windows")
load("kraken/dcerpc", "dcerpc")

def main(ctx):
    identity = ctx.identities["10.0.0.1"]
    auth = windows.ntlm.client(user="alice", password="secret", domain="LAB")

    rpc = dcerpc.tcp(socket.tcp(identity, "10.0.0.5:49664"))
    rpc.bind_auth("367ABB81-9844-35F1-AD32-98F038001003", auth=auth, major=2, minor=0)
    response = rpc.call_auth(0, b"")
    print(response)
    rpc.close()
```

NTLM auth notes:

- `bind_auth` uses the username, password, domain, and NT hash from `windows.ntlm.client(...)`.
- `windows.ntlm.client(..., hash=...)` accepts an NT hash as 32 hex characters, `LM:NT`, or `:NT`.
- `workstation` and `target_spn` remain useful for manual NTLM byte generation, but Mandiant's DCE/RPC NTLM bind path does not currently use those fields.

## Transport Scripts

Transport scripts use `main(packet, ctx)`.

- `ctx.scriptName`, `ctx.adopted`, and `ctx.metadata`
  Active script and adopted identity context.
- Packet layer objects may be `None` when absent:
  `packet.ethernet`, `packet.arp`, `packet.ipv4`, `packet.icmpv4`, `packet.tcp`, `packet.udp`.
- `packet.payload`
  Raw payload bytes. Assign bytes only.
- `packet.copy()`
  Returns a mutable copy of the packet.
- `packet.create_fragments(mtu)`
  Returns packet fragments sized for the requested MTU.
- `packet.pad_payload(length, byte=0)`, `packet.truncate_payload(length)`
  Mutate payload length.
- `packet.send(fix_lengths=True, fix_checksums=True)`
  Emits the current packet snapshot. Packets drop by default unless sent.
- Transport scripts can load `kraken/bytes` and `kraken/time`.

### Packet Fields

- Ethernet:
  `srcMAC`, `dstMAC`, `ethernetType`, `length`.
- ARP:
  `addrType`, `protocol`, `hwAddressSize`, `protAddressSize`, `operation`, `sourceHwAddress`, `sourceProtAddress`, `dstHwAddress`, `dstProtAddress`.
- IPv4:
  `srcIP`, `dstIP`, `version`, `ihl`, `tos`, `length`, `id`, `flags`, `fragOffset`, `ttl`, `protocol`, `checksum`, `options`, `padding`.
- ICMPv4:
  `typeCode`, `type`, `code`, `checksum`, `id`, `seq`.
- TCP:
  `srcPort`, `dstPort`, `seq`, `ack`, `dataOffset`, `flags`, `window`, `checksum`, `urgentPointer`, `options`.
- UDP:
  `srcPort`, `dstPort`, `length`, `checksum`.
- IPv4 and TCP `options` return objects with `type`, `length`, and `data`.

## Runtime Notes

- Reference docs also live in the default script template in the editor.
- Scripts are compiled when loaded or saved.
- Invalid scripts stay visible in their library but cannot be bound or run until fixed.
- Runtime transport script errors are kept as last-error status on the affected adopted identity.
- Generic script runs report stdout and stderr in the Global scripting module and can be stopped from the Run tab.
- Binary packet values are explicit bytes: use Starlark byte literals like `b"\x00\xff"`, `bytes.from_utf8(text)`, or `bytes.concat(...)`. Plain strings are not accepted as packet bytes.
- Numeric packet fields require integers. Length and checksum fields are fixed on send unless explicitly disabled with `fix_lengths=False` / `fix_checksums=False`.
- Unsupported socket options fail clearly; they are not silently ignored.

## Future Scripting Direction

- Keep protocol sessions socket-first. Open sockets with `kraken/socket`, then pass them into protocol adapters.
- Add more pure byte parsers/builders where Mandiant exposes stable APIs.
- Prefer DCE/RPC service wrappers that consume an existing `dcerpc.client`.
- Add SMB named-pipe RPC only after SMB can use adopted identity sockets cleanly.
- Keep Kerberos blocked until DNS, SPN, KDC routing, and credential-cache behavior are identity-aware.
