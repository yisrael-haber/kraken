# Telnet Experiment

This exercises `protocols/telnet` from one Kraken global Lua script, in both roles, against
GNU inetutils on the host, a standard implementation: its `telnetd` and its `telnet` client.
`protocols/telnet` only separates Telnet's commands from the data and answers option
negotiation by the lists the script gives it; the script owns the socket.

- Client: connect to `telnetd`, answer its negotiation by the lists (`terminal_type` for us,
  `echo` and `sga` for them), answer its terminal-type request with a subnegotiation, and read
  up to the `login:` prompt.
- Server: accept the host's `telnet` client, offer to echo, ask for its terminal type, send a
  greeting, read one line and answer it.

Set up the identity as in the [socket experiment](../socket/README.md), including the
`forward.lua` transport, and start it.

On the host, install `telnetd` and `telnet` once (`sudo apt install telnetd telnet`) and run one
command, leaving it running:

```text
sudo sh examples/telnet/host.sh
```

It runs `telnetd` on `192.168.122.1:23` (port 23 needs root; `systemd-socket-activate` starts
it per connection, as inetd would) and then waits for Kraken's server. The `telnetd` package
may also start its own service on port 23: stop it first if the port is busy.

In Kraken, copy `telnet.lua` into a global script and run it. The client stage logs
`client: N negotiations, then the prompt ... login:`. Then the Kraken log shows
`server: waiting for the host's telnet client`, `host.sh` connects with `telnet` and prints
`telnet client to Kraken: OK` and the client's output, and the Kraken log shows what the
client sent and its terminal type and ends with `telnet experiment passed`. If the guest
cannot reach the host or the reverse, allow TCP port 23 in the host firewall.

## Wireshark

Capture on the libvirt bridge (`virbr0`) with the filter `tcp.port == 23`. Wireshark decodes
Telnet on port 23. Look for:

- From `telnetd`, a burst of `Do` and `Will` options (terminal type, echo, suppress go-ahead,
  environment, ...) in one packet, and Kraken's answers: `Will Terminal Type` (accepted),
  `Do Echo`, `Do Suppress Go Ahead`, and `Wont` or `Dont` for everything else.
- `Suboption Terminal Type: Send` from `telnetd`, answered by `Suboption Terminal Type: Is XTERM`.
- Then the banner and the `login:` prompt as plain data.
- In the server stage, Kraken's `Will Echo`, `Will Suppress Go Ahead` and `Do Terminal Type`, the
  client's answers, `Suboption Terminal Type: Send`, the client's terminal name, and the
  greeting. The client's line, `hello`, arrives with CR LF, and Kraken's answer follows.
