# lwIP source snapshot

Source: `https://github.com/lwip-tcpip/lwip` (mirror of Savannah)

Tag: `STABLE-2_2_1_RELEASE`

Commit: `77dcd25a72509eb83f72b033d219b1d40cd8eb95`

Upstream source tree, platform ports, and add-ons, with no source changes. Upstream tests,
examples, and extended documentation are omitted. `COPYING` contains the license.
Kraken currently compiles the IPv4 core, socket API, Ethernet interface, and
the Unix or Win32 OS port. Local configuration and C bindings live in `kraken/`;
the Zig virtual-interface adapter lives in `src/net/`.
