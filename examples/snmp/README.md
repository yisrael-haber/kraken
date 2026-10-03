# SNMP Experiment

This exercises `protocols/snmp` from one Kraken global Lua script, in every role a script can
play, against net-snmp on the host, the standard implementation. `protocols/snmp` only turns
SNMP v1 and v2c messages into bytes and back; the script owns the UDP sockets and decides what
to send and how to read the answers.

- Manager: `get` of seven typed values (octet string, OID, time ticks, integer, counter32,
  counter64); the errors, which differ by version (noSuchObject in v2c, noSuchName in v1, a
  refused `set`); `getnext`, `getbulk` and walks of the system group, the interfaces and the
  address table, written in Lua; and a wrong community string, which gets no answer.
- Traps: a v2c trap and a v1 trap, sent to `snmptrapd`.
- Agent: a Lua table of values answers `snmpget`, `snmpgetnext` and `snmpbulkget` from the host.

Set up the identity as in the [socket experiment](../socket/README.md), including the
`forward.lua` transport, and start it.

On the host, install net-snmp once (`sudo apt install snmpd snmptrapd snmp`) and run one command, leaving
it running:

```text
sudo sh examples/snmp/host.sh
```

It starts `snmpd` on `192.168.122.1:161` (community `public`) and `snmptrapd` on port `162`, then
waits for Kraken's agent. Ports 161 and 162 need root. The script stops the system `snmpd` and
`snmptrapd` services, which the packages start on install and which hold the ports. If the guest cannot reach the host or the reverse, allow UDP ports 161
and 162 in the host firewall.

In Kraken, copy `snmp.lua` into a global script and run it. The manager stages log a line each
and `snmptrapd` prints both traps. Then the Kraken log shows
`agent: waiting for snmpget, snmpgetnext and snmpbulkget`, and `host.sh` prints
`snmpget sysDescr from Kraken: OK`, `snmpgetnext from sysDescr: OK` and the bulk result, ending
`snmpbulkget over the system group: OK`. The Kraken log ends with `snmp experiment passed`.

## Wireshark

Capture on the libvirt bridge (`virbr0`) with the filter `snmp`. Both ports are the standard
ones, so Wireshark decodes SNMP without any setup. Look for:

- `get-request` messages (version `v2c`, community `public`) answered by `get-response`; the
  value types appear as `octet-string`, `timeticks`, `integer-value`, `counter` and `counter64`.
- A missing object: `noSuchObject` as the value in v2c, but `error-status: noSuchName (2)` in v1.
- `getBulkRequest` with `max-repetitions: 3`, answered by three varbinds.
- A walk is a series of `get-next-request` messages, each asking for the OID the last answer
  returned, ending outside the subtree.
- The wrong community string, `private`, with no `get-response` at all.
- A `snmpV2-trap` and a v1 `trap` to port 162, with no reply.
- The host's requests to Kraken's port 161, answered from the Kraken script.
