# SSH Experiment

This serves a single command to the host's OpenSSH client, exercising
`protocols/ssh` as a server: the handshake, the `authorize` callback, reading
the requested command, sending output, and the exit status.

Set up the identity as in the [socket experiment](../socket/README.md),
including the `forward.lua` transport, and start it.

In Kraken, copy `server.lua` into a global script (adjust the two values at the
top if your identity differs) and run it. It embeds a lab host key, so no setup
is needed. When the log shows `server: waiting for an SSH client`, run on the
host:

```text
ssh -p 19096 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    user@192.168.122.5 "hello from the host"
```

The host `ssh` offers a public key (or falls back), which the script's
`authorize` accepts, then runs the command. The host prints:

```text
kraken ran: hello from the host
```

and the Kraken log ends with `ssh experiment passed`. A failed `assert` or a
mismatched line names what differed. Client-side `protocols/ssh` (running a
command on a remote server) uses password auth; point `ssh.connect` at an SSH
server that accepts it.

The embedded key is for lab use only. Generate your own DER key with:

```text
openssl ecparam -name prime256v1 -genkey -noout -outform DER -out host.der
od -An -v -tx1 host.der | tr -d ' \n'
```
