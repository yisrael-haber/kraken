# wolfSSH source snapshot

Source: `https://github.com/wolfSSL/wolfssh`

Tag: `v1.5.0-stable`

Commit: `8643d7be841184f766374e3b0ed68ced6391543c`

License: GPLv3 (`LICENSING`), the same license wolfIP and wolfSSL place on Kraken.

Upstream files are unchanged. Only what the build uses is kept: `src/internal.c`,
`src/io.c`, `src/log.c`, `src/misc.c`, `src/port.c`, `src/ssh.c`, and the headers
those sources include on Linux and Windows. SFTP, SCP, the terminal, the agent,
the certificate manager and key generation are not vendored. `protocols/ssh`
uses the exec subset of the API with Kraken's I/O callbacks.

## Kraken files

- `kraken/ssh_shim.h` and `kraken/ssh_shim.c` read and set `WS_UserAuthData`
  fields from C. Its bitfield union translates to an opaque type in Zig.

## Configuration

wolfSSH has no config file of its own; it builds against the vendored wolfSSL and
its `kraken/user_settings.h`. The build passes `-DWOLFSSL_USER_SETTINGS`,
`-DWOLFSSH_SHELL` (compiles in the exit-status API used by exec), and
`-DWOLFSSH_USER_IO` (compiles out wolfSSH's default socket I/O, so it makes no OS
socket calls). On Windows the wolfSSL `user_settings.h` includes `<winsock2.h>`
for the `SOCKET` type wolfSSH keeps in its session struct.

## Note

With custom I/O callbacks, `protocols/ssh` sets the I/O context with
`wolfSSH_SetIOReadCtx`/`SetIOWriteCtx` and never calls `wolfSSH_set_fd`, which
would overwrite that context.

## Updating

Replace the kept files with the new release's copies, then add any file the new
release's sources include that is missing. The build fails with the name of each
missing file.
