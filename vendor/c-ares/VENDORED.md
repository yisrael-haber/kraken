# c-ares source snapshot

Source: `https://github.com/c-ares/c-ares`

Commit: `5b181482e5b6d1dc04d1e899dd2c3a9f5695ce62` (1.34.5)

Only the DNS record codec is kept: `src/lib/record/` with the buffer, string,
array, list and math helpers it uses, `ares_strerror.c`, `ares_free_string.c`,
`ares_library_init.c`, and the public and private headers. The resolver,
sockets, event loop and system configuration code are not vendored.
`protocols/dns` uses the record API (`ares_dns_parse`, `ares_dns_write`, and the
`ares_dns_rr_*` key accessors).

## Kraken files

- `kraken/ares_build.h` and `kraken/ares_config.h` replace the CMake-generated
  headers, keeping only what the record codec needs. Linux compiles with
  `HAVE_CONFIG_H`; Windows uses the upstream `src/lib/config-win32.h`. After an
  update, a missing entry shows up as a build error, or as a `macro redefined`
  warning for `AF_INET6` and `PF_INET6`.
- `kraken/ares_stub.c` provides `ares_is_onion_domain`, which lives in the
  unvendored resolver and is referenced by a record helper Kraken never calls.

## Local changes

`kraken/records.patch` holds the diff against upstream. Re-apply it after an
update. It makes the codec accept every well-framed message, which the
resolver-oriented checks rejected:

- `ares_dns_mapping.c`: `ares_dns_class_isvalid` accepts every class (mDNS sets
  the top bit), `ares_dns_opcode_isvalid` every 4-bit opcode (NBT-NS uses 5-8),
  and `ares_dns_rcode_isvalid` every 12-bit rcode.
- `ares_dns_parse.c`: messages with zero or several questions are accepted
  (mDNS and NBT-NS use both).
