# OpenLDAP source snapshot

Source: `https://www.openldap.org/software/download/OpenLDAP/openldap-release/`

Release: `openldap-2.6.15` (tarball sha256
`bc91225dbfc50354033b1303bc91d1a7f6ddd1dc32fac950d79c28fe66d6bca8`), the 2.6 LTS series.

License: OpenLDAP Public License (`LICENSE`, `COPYRIGHT`).

Only the client libraries are kept, with no source changes:

- `libraries/liblber`: the BER codec, seven files.
- `libraries/libldap`: the LDAP client, 36 files (everything `protocols/ldap` links,
  found by linking a program that uses every API the module calls).
- `include/`: the upstream headers those files include, and
  `libraries/liblunicode/ucdata/ucdata.h`, which one of them includes.

## Kraken files

`kraken/` holds what OpenLDAP's `configure` generates. libldap is built without
threads, TLS, SASL, the debug log and local sockets:

```text
./configure --disable-slapd --disable-debug --disable-syslog --disable-ipv6 \
    --disable-local --disable-shared --enable-static --without-cyrus-sasl \
    --without-tls --without-threads --without-fetch --without-systemd \
    --without-argon2 --disable-dynamic
```

- `kraken/linux/portable.h`: generated on Linux.
- `kraken/windows/portable.h`: generated cross-compiling with `zig cc -target
  x86_64-windows-gnu` and `--host=x86_64-w64-mingw32` (the configure regex check
  needs `ac_cv_header_regex_h=yes`). Configure cannot test `memcmp` when cross
  compiling and assumes it is broken, so `NEED_MEMCMP_REPLACEMENT` is `#undef`ed by hand.
- `kraken/ldap_features.h`, `lber_types.h`, `ldap_config.h`: identical for both
  platforms. `ldap_config.h` comes from `make ldap_config.h` in `include/`.

`build.zig` compiles the library as `kraken-ldap`. After an update, regenerate
these headers the same way and rebuild; a source file that a new release needs
shows up as an undefined symbol.
