# TCP and UDP Socket Experiment

This uses a host Python peer and one Kraken global Lua script in a guest VM.
It verifies TCP connect, send, exact receive, and close; then connected UDP
send, datagram receive, source address, source port, and close.

Choose one reachable IPv4 network shared by the host and guest. Configure a
Kraken identity in the guest with an unused IPv4 address on that network and
the guest capture interface. The host address must be reachable from that
identity. This experiment uses port `19090`.

On the host, start the peer with its reachable IPv4 address:

```text
python3 examples/socket/peer.py --bind 192.0.2.1
```

In Kraken, create a transport script from `forward.lua` and select it for the
test identity. It forwards every frame and proves that socket traffic follows
the identity transport path. Start the identity.

Copy `tcp_udp.lua` into a global script and change these values:

```lua
local identity = "researcher" -- the configured guest identity name
local host = "192.0.2.1"     -- the host address passed to peer.py
```

Run the global script. Success produces `socket experiment passed` in both the
host terminal and Kraken log. The host also prints TCP and UDP requests from
the Kraken identity address.

To verify transport enforcement, replace the forwarding script with:

```lua
function transport(packet, direction)
end
```

Run the global script again. TCP connect must time out and the host must
receive no request. Restore `forward.lua` before the successful run.
