# Protocol Integration

Kraken exposes small protocol primitives to scripts. It is not a collection of copied command-line workflows.

## Current Surface

- `kraken/socket` opens TCP and UDP sockets through an adopted identity.
- `kraken/windows` provides Windows-focused byte helpers: SID and security descriptor parsing, NTLM messages, TDS packets, and UTF-16LE conversion.
- `kraken/dcerpc` provides TCP DCE/RPC bind/call, NTLM-authenticated bind/call, and endpoint mapper lookup.

See [scripting.md](scripting.md) for the callable API.

## Research Model

Open the socket first, then give that connection to a protocol helper. This keeps the chosen adopted identity visible and prevents protocol helpers from silently using the host network.

```python
conn = socket.tcp(identity, "10.0.0.5:135")
rpc = dcerpc.tcp(conn)
rpc.bind("12345678-1234-5678-90ab-cdef01234567")
```

TCP DCE/RPC is intentionally low-level: scripts provide interface UUIDs, operation numbers, and request bytes. Endpoint mapper lookup filters returned bindings; the script still opens the selected socket itself.

## Not Available

- SMB named-pipe RPC.
- Kerberos RPC.
- Protocol helpers that discover, resolve, or dial targets on their own.
- High-level service-specific workflows that hide requests or output policy.
