# LDAP Experiment

This exercises `protocols/ldap` from one Kraken global Lua script against a
throwaway OpenLDAP server on the host. It binds (anonymous, wrong password,
admin), binds as an ordinary user and shows that the bind decides what the session can
read and write, repeats a bind and a search over LDAPS (TLS), then searches, adds, modifies, renames, compares and deletes entries,
and handles a 100 KB value and 150 entries.

## Host: start the server

Install OpenLDAP once (Debian and Ubuntu: `sudo apt install slapd`; if it asks for an
administrator password, anything will do, this experiment does not use that
instance). Then, from the repository root, leave this running in a terminal:

```text
sh examples/ldap/slapd.sh
```

It listens for LDAP on `192.168.122.1:3890` and LDAPS on `192.168.122.1:6360`, prints each connection and operation, and stops
with Ctrl+C. If it exits with a permission error on Ubuntu, AppArmor is confining
`slapd`: run `sudo aa-complain /usr/sbin/slapd` once and start it again. If the guest
cannot connect, allow TCP ports `3890` and `6360` in the host firewall.

## Kraken

Set up the identity as in the [socket experiment](../socket/README.md), including
the `forward.lua` transport, and start it. Copy `ldap.lua` into a global script and
run it; its identity and host values already match the other experiments. Each
stage logs a line, and success ends with `ldap experiment passed`. A refused
operation raises an error that names the LDAP result, for example
`LDAP bind failed: Invalid credentials (49)`. The script leaves the directory as it
found it, so it can run again.

## Wireshark

Capture on the libvirt bridge (`virbr0`) with the filter `tcp.port == 3890`. Wireshark
decodes LDAP on port 389 only: right-click a packet, choose Decode As, and set TCP
port 3890 to LDAP. The traffic is plain text, so the whole conversation is readable.
Look for, in order:

- `bindRequest` with an empty name (anonymous), answered `success`.
- `bindRequest` for `cn=admin,dc=example,dc=com` with a wrong password, answered
  `invalidCredentials (49)`; the TCP connection stays open.
- `bindRequest` with the right password, answered `success`.
- `extendedReq` `1.3.6.1.4.1.4203.1.11.3` ("who am I"), answered with
  `dn:cn=admin,dc=example,dc=com`.
- An anonymous `searchRequest` for `ou=people` answered `noSuchObject (32)` with no
  entries (the server hides what anonymous may not read), then a `bindRequest` for `cn=alice,ou=people,dc=example,dc=com` with
  password `alicepw` (readable in the packet, since it is plain text), answered
  `success`, a "who am I" answered `dn:cn=alice,...`, and the same search now
  returning two `searchResEntry` messages.
- An `addRequest` sent as alice answered `insufficientAccessRights (50)`, and a
  `bindRequest` for alice with a wrong password answered `invalidCredentials (49)`.
- `searchRequest` messages with scope `singleLevel`, `baseObject` and `wholeSubtree`,
  each followed by `searchResEntry` messages and one `searchResDone`.
- `addRequest`, `modifyRequest` (replace, add and delete), `modDNRequest` (the
  rename), `compareRequest` (`compareTrue` and `compareFalse`), `delRequest`.
- The 100 KB value arrives as one `searchResEntry` spread over many TCP segments.
- A final `unbindRequest`, then the connection closes.
- The LDAPS stage, on `tcp.port == 6360`: a TLS handshake (ClientHello with server
  name `kraken.test`, ServerHello, the lab certificate) and then only encrypted
  application data. No LDAP messages are readable there, which is the point; the
  server log still shows the bind, search and refused write.

If something fails, send me the Kraken log and the terminal output of `slapd.sh`;
that pair shows whether the client or the server stopped first.
