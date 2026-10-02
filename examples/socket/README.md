# TCP and UDP Socket Experiment

This uses one Python peer and one Kraken global Lua script across a host and VM.
It verifies TCP connect, send, exact receive, and close; then connected UDP
send, datagram receive, source address, source port, and close.

Choose one reachable IPv4 network shared by the host and VM. Configure a
Kraken identity with an unused IPv4 address on that network and the matching
capture interface. The peer address must be reachable from that
identity. This experiment uses port `19090`.

On the peer machine, start the peer with its reachable IPv4 address:

```text
python3 examples/socket/peer.py --bind 192.0.2.1
```

In Kraken, create a transport script from `forward.lua` and select it for the
test identity. It repairs supported checksums before forwarding, including
incomplete checksums captured on VM links. Start the identity.

Copy `tcp_udp.lua` into a global script and change these values:

```lua
local identity = "researcher" -- the configured guest identity name
local host = "192.0.2.1"     -- the peer address passed to peer.py
```

## VM checklist

1. Run the global script. Both the peer terminal and Kraken log should print
   `socket experiment passed`. The peer should show TCP and UDP requests from
   the identity's IPv4 address.
2. Stop and start the same identity. Restart `peer.py` on the peer machine
   (it exits after one run), then run the same global script again. Expect the
   same result, with no socket errors or timeouts.
