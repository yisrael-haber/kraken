#!/bin/sh
# The host's end of the Telnet experiment, with GNU inetutils, a standard implementation:
#   sudo sh examples/telnet/host.sh
# It runs telnetd on 192.168.122.1:23, which Kraken's script connects to, then, once the
# script is running its own server, connects to it with the host's telnet client.
# Port 23 and telnetd need root. Needs: sudo apt install telnetd telnet
# systemd-socket-activate plays inetd, which is how telnetd expects to be started.
set -e

HOST=192.168.122.1
KRAKEN=192.168.122.5

if [ "$(id -u)" != 0 ]; then echo "run it with sudo: port 23 and telnetd need root"; exit 1; fi
for tool in systemd-socket-activate telnet /usr/sbin/telnetd; do
    if ! command -v "$tool" > /dev/null; then echo "$tool not found: sudo apt install telnetd telnet"; exit 1; fi
done

systemd-socket-activate --inetd --accept --listen "$HOST:23" /usr/sbin/telnetd --no-hostinfo &
SERVER=$!
trap 'kill $SERVER 2> /dev/null' EXIT INT TERM

echo "telnetd on $HOST:23; waiting for Kraken's server on $KRAKEN:23 ..."
echo "Run telnet.lua in Kraken now."
until out=$( (sleep 1; printf 'hello\n'; sleep 2) | telnet "$KRAKEN" 23 2>&1) && printf '%s\n' "$out" | grep -q -F "Kraken telnet server"; do sleep 1; done

if printf '%s\n' "$out" | grep -q -F "you said: hello"; then echo "telnet client to Kraken: OK"; else echo "telnet client to Kraken: WRONG"; fi
printf '%s\n' "$out"
echo "done; stopping telnetd"
