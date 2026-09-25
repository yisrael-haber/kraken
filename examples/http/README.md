# HTTP and HTTPS Experiment

This uses a host Python peer and one Kraken global Lua script in a guest VM to
exercise `protocols/http` in both directions, first over a TCP socket and then,
unchanged, over a `protocols/tls` session:

- Client: GET `/plain` (`Content-Length` body, duplicate headers) and
  `/chunked` (chunked body) from the host, on port `19091` (HTTP) and `19093`
  (HTTPS). Over HTTPS, Kraken verifies the host's certificate for
  `kraken.test` and negotiates ALPN `http/1.1`.
- Server: accept a POST from the host on port `19092` (HTTP) and `19094`
  (HTTPS), parse it, and answer. Over HTTPS, the host verifies Kraken's
  certificate and Kraken checks the requested server name (SNI) and ALPN.

Both sides use the self-signed lab certificate for `kraken.test` in
`src/protocols/testdata`, which `http.lua` also embeds. Use it only for lab
testing.

Set up the identity as in the [socket experiment](../socket/README.md),
including the `forward.lua` transport, and start it.

On the host:

```text
python3 examples/http/peer.py --bind 192.168.122.1 --kraken 192.168.122.5
```

In Kraken, copy `http.lua` into a global script. Adjust the three values at the
top if your identity differs:

```lua
local identity = "base_192.168.122.5"
local address = "192.168.122.5"
local host = "192.168.122.1"
```

Run it. Success prints `http experiment passed` in the Kraken log and
`http experiment passed (host side)` in the host terminal. A failed `assert`
names the line that failed. If a client part times out, allow TCP ports `19091`
and `19093` in the host firewall.
