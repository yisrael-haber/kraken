# Mandiant gopacket Integration

This document captures the intended integration shape for Mandiant's Go protocol packages inside Kraken. The goal is to keep Kraken powerful without turning it into a pile of copied command-line tools or hidden network paths.

## Core Rules

- Keep socket creation in `kraken/socket`.
  Protocol modules should consume open script sockets or existing protocol clients. They should not dial by IP, hostname, or domain controller on their own.
- Preserve adopted identity ownership.
  If traffic leaves Kraken, the script should make it obvious which adopted identity owns the socket.
- Prefer byte parsers/builders before high-level workflows.
  Pure byte helpers are low-risk, easy to test, and useful in both global and transport scripts.
- Prefer wrappers around existing clients.
  A Mandiant package that accepts an existing `net.Conn` or `*dcerpc.Client` is a good candidate. A package that owns dialing, DNS, auth, and output needs adaptation before exposure.
- Keep auth explicit.
  Authenticated DCE/RPC should use explicit `bind_auth(...)` and `call_auth(...)` until there is a strong reason to auto-dispatch.
- Do not clone Mandiant tools one-for-one.
  Tools mix dialing, auth, parsing, command flags, output, retries, and workflow. Kraken should expose composable scripting primitives first.

## Current Integration

- `kraken/windows`
  Exposes SID, security descriptor, ACL/ACE, NTLM byte generation, TDS packet/pre-login helpers, and UTF-16LE helpers.
- `kraken/dcerpc`
  Exposes socket-first TCP DCE/RPC, raw bind/call, NTLM-authenticated bind/call, endpoint mapper lookup, endpoint filtering, and structured TCP bindings.
- `kraken/socket`
  Owns identity-backed TCP/UDP creation and socket options.

## High-Impact Next Work

1. DCE/RPC NTLM polish
   - Add authenticated state fields such as `client.authenticated` and `client.auth_type`.
   - Improve bind failure messages, especially RPC faults and NTLM challenge/authenticate failures.
   - Document known interface UUIDs for SAMR, LSA, SRVSVC, SVCCTL, TSCH, WINREG, and DRSUAPI.
   - Keep `call_auth(...)` explicit unless users prove automatic dispatch is less error-prone.

2. Existing-client DCE/RPC service wrappers
   - Inspect Mandiant packages for constructors that accept `*dcerpc.Client`.
   - Good first candidates are read-only operations from SAMR, LSA, SRVSVC, or SVCCTL.
   - Expose small constructors only when no hidden dialing is introduced:
     ```python
     rpc.bind_auth(samr_uuid, auth=auth, major=1, minor=0)
     samr = dcerpc.samr(rpc)
     print(samr.enumerate_domains())
     ```
   - Keep wrappers narrow. Do one useful read-only workflow before adding mutation.

3. SMB named-pipe DCE/RPC
   - This is the biggest compatibility gap after TCP DCE/RPC.
   - Many Windows RPC services are commonly exposed over named pipes such as `\\pipe\\samr`, `\\pipe\\lsarpc`, `\\pipe\\svcctl`, `\\pipe\\atsvc`, and `\\pipe\\winreg`.
   - Only proceed if Mandiant SMB can use an existing `net.Conn` or a narrow dialer that can route through adopted identity sockets.
   - The desired script shape is still socket-first:
     ```python
     smb_conn = socket.tcp(identity, "10.0.0.5:445")
     smb = windows.smb.client(smb_conn, auth=auth)
     pipe = smb.pipe(r"\\pipe\\samr")
     rpc = dcerpc.pipe(pipe)
     ```

4. Pure packet/protocol parsing helpers
   - NTLM message parsing: negotiate/challenge/authenticate summaries.
   - More Windows security helpers when backed by stable Mandiant APIs.
   - Kerberos ticket or ccache parsing if pure-byte APIs are available.
   - LDAP ASN.1 helpers only if the package provides structured parser APIs with limited dependency cost.
   - TDS login/pre-login parsing and generation improvements.

5. Credential object unification
   - `windows.ntlm.client(...)` currently works as both byte generator and DCE/RPC auth input.
   - If more auth surfaces appear, introduce a credentials object:
     ```python
     creds = windows.credentials.ntlm(user="alice", password="secret", domain="LAB")
     ntlm = windows.ntlm.client(creds=creds)
     rpc.bind_auth(uuid, auth=creds)
     ```
   - Do this only when it removes real duplication across SMB, DCE/RPC, LDAP, or Kerberos.

## Kerberos Position

Kerberos should not be exposed yet just because Mandiant has DCE/RPC Kerberos functions.

Before exposing it, Kraken needs a clear answer for:

- Which adopted identity owns KDC traffic?
- How hostname and SPN are selected.
- Whether DNS lookup happens through an adopted identity, host resolver, or explicit IP mapping.
- How ccache/keytab/password inputs are represented in scripts.
- How cross-realm or DC selection behaves.

Until those are solved, Kerberos wrappers risk being confusing, host-network dependent, or silently outside the adopted identity path.

## Compatibility Targets

Use Linux-native targets first, then Windows for reference behavior.

- Samba AD DC on Linux
  Best first target for endpoint mapper, NTLM, SMB, SAMR/LSA/SRVSVC-style behavior, and future Kerberos.
- Windows Server evaluation VM
  Best reference target for DCE/RPC compatibility and edge cases.
- SQL Server on Linux/container
  Good target for TDS packet/pre-login helpers.

External tools useful for comparison:

- `rpcdump.py`
- `rpcclient`
- `smbclient`
- `lookupsid.py`
- `samrdump.py`

When behavior differs, treat Windows as the reference and Samba as the fast iteration target.

## Avoid For Now

- Auto-dialing protocol helpers.
- One-shot ports of Mandiant command-line tools.
- Kerberos DCE/RPC before identity-aware DNS/SPN/KDC routing exists.
- SMB/RPC wrappers that hide native dialing.
- Large high-level service clients before one small read-only wrapper proves the shape.
- Test-only production abstractions for fake protocol clients.

## Evaluation Checklist For A New Mandiant Package

1. Does it accept an existing `net.Conn`, `io.ReadWriter`, or `*dcerpc.Client`?
2. If it dials internally, can a narrow dialer be injected without broad wrappers?
3. Does it provide pure parsing/building APIs that are useful without network I/O?
4. Does it force DNS, KDC, or host resolver use outside Kraken identity sockets?
5. Does it introduce a large dependency surface for a small scripting feature?
6. Can the script API be described in one or two direct examples?
7. Does it preserve the rule that socket creation belongs to `kraken/socket`?
