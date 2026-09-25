# DNS Experiment

This exercises `protocols/dns` against two independent DNS implementations:

- Client: Kraken queries the host's resolver (libvirt's dnsmasq on
  `192.168.122.1:53`) for `example.com` and decodes the reply. Any rcode
  passes; without upstream internet dnsmasq may answer with an error rcode.
- Server: Kraken listens on UDP `10053` and answers one query for
  `kraken.test` (`A 192.0.2.53`, or a TXT record), which `dig` on the host
  must accept.

Set up the identity as in the [socket experiment](../socket/README.md),
including the `forward.lua` transport, and start it.

In Kraken, copy `dns.lua` into a global script, adjust the three values at the
top if your identity differs, and run it. When the log shows
`server: waiting for a query`, run on the host (`dig` is in `bind9-dnsutils`
or `bind-utils`):

```text
dig @192.168.122.5 -p 10053 kraken.test
```

`dig` must show `kraken.test. 60 IN A 192.0.2.53` with the `aa` flag, and the
Kraken log ends with `dns experiment passed`. For the TXT answer, run the
script again and use `dig @192.168.122.5 -p 10053 kraken.test TXT`.
