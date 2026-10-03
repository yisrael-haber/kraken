# SIP Experiment

This exercises `protocols/sip` from one Kraken global Lua script, in both roles, against
SIPp, the standard SIP test tool, on the host. `protocols/sip` only turns messages into
tables and back, with oSIP; the script owns the UDP socket, the transactions and the dialog.

- Client: against `sipp -sn uas`, send an OPTIONS (answered 200), an INVITE with SDP (answered
  180 and 200 with SDP and a tag), and, as the dialog requires, an ACK and a BYE to the
  contact and the tagged `To` (answered 200). Each response must carry the request's
  branch, CSeq and Call-ID.
- Server: answer `sipp -sn uac`: its INVITE with 180 and 200 and SDP, built from the request
  by copying its Via, From, Call-ID and CSeq and tagging To, then its ACK and its BYE with 200.

Set up the identity as in the [socket experiment](../socket/README.md), including the
`forward.lua` transport, and start it.

On the host, install SIPp once (`sudo apt install sip-tester`) and run one command, leaving it
running (it needs no root):

```text
sh examples/sip/host.sh
```

It runs a SIPp user agent server on `192.168.122.1:5060` and then waits for Kraken's server.

In Kraken, copy `sip.lua` into a global script and run it. The client stage logs a line for
each of OPTIONS, INVITE and BYE. Then the Kraken log shows
`server: waiting for SIPp's INVITE`, `host.sh` calls Kraken with a SIPp user agent client and
prints `SIPp client call to Kraken: OK` and `SIPp server call from Kraken: OK`, and the Kraken
log ends with `sip experiment passed`. To run it again, restart `host.sh`. If the guest cannot
reach the host or the reverse, allow UDP ports 5060 and 5061 in the host firewall.

## Wireshark

Capture on the libvirt bridge (`virbr0`) with the filter `sip`. Wireshark decodes SIP on UDP
5060 and follows the call with Telephony, VoIP Calls. Look for:

- `Request: OPTIONS`, `Status: 200 OK`, with the same `branch=z9hG4bK-kraken-1` in the Via of
  both.
- `Request: INVITE` with `Content-Type: application/sdp` and a `v=0` body, then `Status: 180
  Ringing` and `Status: 200 OK` with SDP and `tag=` in the `To` header.
- `Request: ACK` and `Request: BYE` sent to the contact URI from the 200, with the same
  Call-ID, a CSeq of 2 for the ACK and 3 for the BYE, and the tagged `To`.
- In the server stage, SIPp's INVITE, Kraken's 180 and 200 (with the request's Via and CSeq
  copied and `tag=kraken-uas` added to `To`), then SIPp's ACK and BYE and Kraken's 200.
