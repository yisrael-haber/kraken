# TFTP Experiment

This exercises `protocols/tftp` from one Kraken global Lua script, in both roles, against
one small Python script on the host (`peer.py`, standard library only). `protocols/tftp` only
turns packets into bytes and back; the script owns the UDP sockets and runs TFTP's
lock-step transfer itself.

- Client: read a 2500-byte file, again with a `blksize` option (so the server answers
  with an OACK), and a 1024-byte file that is an exact multiple of the block size (so the
  transfer must end on an empty block); a missing file must raise `File not found`.
  Then write a 3000-byte file with and without `blksize`.
- Server: answer one read request (`kraken.bin`) and one write request (`incoming.bin`)
  from the peer, each from a new port, as TFTP requires.

Set up the identity as in the [socket experiment](../socket/README.md), including the
`forward.lua` transport, and start it.

On the host, run the peer, one command, and leave it running:

```text
python3 examples/tftp/peer.py
```

It serves Kraken's client requests, and after the sixth it becomes the client of Kraken's
server by itself, so nothing else needs starting.

In Kraken, copy `tftp.lua` into a global script and run it. The client stages run first
and each logs a line, while the peer prints `served ...` for each read and
`stored upload.bin: 3000 bytes OK` for each write. Then the Kraken log shows
`server: waiting for a read and a write request`, and the peer prints
`got kraken.bin from Kraken: 1500 bytes OK` and `sent incoming.bin to Kraken: 2200 bytes`.
The Kraken log ends with `tftp experiment passed`. To run it again, restart the peer. If the
guest cannot reach the host or the reverse, allow UDP ports `6969`, `6970` and `6971-6981`
in the host firewall.

## Wireshark

Capture on the libvirt bridge (`virbr0`) with the filter `udp.port == 6969 || udp.port == 6970`.
Wireshark decodes TFTP on port 69 only: right-click a packet, choose Decode As, and set UDP
port 6969 (and 6970) to TFTP. Transfers continue from other ports (the transfer IDs); the
first reply to a request tells Wireshark to follow them. Look for:

- A read request (`Read Request, File: download.bin, Transfer type: octet`), then `Data Packet`
  and `Acknowledgement` pairs, each block 512 bytes, the last one shorter (452 bytes).
- With the `blksize` option the server answers `Option Acknowledgement` (`blksize=1024`),
  Kraken sends `Acknowledgement, Block: 0`, and the data blocks are 1024 bytes.
- `exact.bin` ends with a `Data Packet` of zero bytes after two full 512-byte blocks.
- The missing file gets `Error Code, Code: File not found`, from the server's new port.
- A write request is answered by `Acknowledgement, Block: 0` (or an OACK), and Kraken's
  data blocks then go to the port that answered, not to the request port.
