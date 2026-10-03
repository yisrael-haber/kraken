# Mail Experiment

This exercises `protocols/smtp`, `protocols/pop3` and `protocols/imap` from one Kraken global Lua
script against standard servers on the host: aiosmtpd for SMTP and Dovecot for POP3 and IMAP. Both protocols run in
libetpan, vendored in `vendor/libetpan`, which Kraken gives a TCP socket (or a TLS session for
SMTPS and POP3S) instead of its own; the script is the client.

- SMTP: connect, say EHLO as `kraken.lab` (not the host's name), check what the server offers,
  and send one message with a dot-leading line to two recipients.
- POP3: a wrong password is refused with the server's reply; then log in, `stat`, `list` (with
  UIDLs), `retrieve` the first message, read the head of the second with `top`, `delete` it and
  `reset`.
- IMAP: a wrong password is refused; then log in, `list`, `select` (two messages), `search`,
  `fetch` flags, UIDs, sizes, heads and a body, `store` `\Seen` and find the message again by
  searching for `seen`, `append` a message, `select` again to see it, delete and `expunge` it,
  and create and delete a mailbox.

Set up the identity as in the [socket experiment](../socket/README.md), including the
`forward.lua` transport, and start it.

On the host, install the servers once
(`sudo apt install dovecot-pop3d dovecot-imapd python3-aiosmtpd`) and run one command, leaving it
running:

```text
sudo sh examples/mail/host.sh
```

It writes a Dovecot 2.4 configuration and two messages for the user `test` (password `secret`) to
`/tmp/kraken-mail`, then runs Dovecot (POP3 on `192.168.122.1:110`, IMAP on `:143`) and aiosmtpd (SMTP
on port 25). Ports 25, 110 and 143 need root. The packages start their own Dovecot service, which the script stops.

In Kraken, copy `mail.lua` into a global script and run it. The log shows a line for the SMTP send
(with the server's `250 OK`), for each refused password, and for the POP3 and IMAP sessions, and ends with
`mail experiment passed`. `host.sh` then prints the message aiosmtpd received and Dovecot's log of the
POP3 and IMAP sessions, and stops. To run it again, restart `host.sh`. If the guest cannot reach the host,
allow TCP ports 25, 110 and 143 in the host firewall.

## Wireshark

Capture on the libvirt bridge (`virbr0`) with the filter `smtp || pop || imap`. Look for:

- `EHLO kraken.lab`, the server's `250-` lines (`SIZE`, `8BITMIME`, ...), `MAIL FROM:<kraken@lab.test>`,
  one `RCPT TO` for each recipient, `DATA`, then the message ending in a lone `.`, with the line that
  starts with a dot sent as `..line two starts with a dot`.
- In POP3, `USER test`, `PASS wrong` answered `-ERR`, then a second connection with `PASS secret`
  answered `+OK`, `STAT`, `LIST`, `UIDL`, `RETR 1`, `TOP 2 1`, `DELE 2`, `RSET` and `QUIT`.
- In IMAP, tagged commands (`1 LOGIN`, `2 LIST`, `3 SELECT INBOX`, ...) with untagged replies (`* 2 EXISTS`),
  `FETCH 1:2 (FLAGS UID RFC822.SIZE BODY.PEEK[HEADER])`, `STORE 1 +FLAGS.SILENT (\Seen)`, `APPEND INBOX {N}`
  answered `+ ...` before the message is sent, `EXPUNGE` and `LOGOUT`.
