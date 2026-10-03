#!/bin/sh
# The host's end of the SIP experiment, with SIPp, the standard SIP test tool:
#   sh examples/sip/host.sh
# It runs a SIPp user agent server on 192.168.122.1:5060 for Kraken's client, then, once Kraken's
# script is running its own server, calls it with a SIPp user agent client.
# Needs SIPp: sudo apt install sip-tester
set -e

HOST=192.168.122.1
KRAKEN=192.168.122.5
DIR=/tmp/kraken-sip

if ! command -v sipp > /dev/null; then echo "sipp not found: sudo apt install sip-tester"; exit 1; fi

rm -rf "$DIR"
mkdir -p "$DIR"
# -aa answers OPTIONS by itself; the call (INVITE to BYE) is the one call it waits for.
sipp -sn uas -aa -i "$HOST" -p 5060 -m 1 -nostdin -timeout 300s > "$DIR/uas.txt" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2> /dev/null' EXIT INT TERM

echo "SIPp user agent server on $HOST:5060; waiting for Kraken's server on $KRAKEN:5060 ..."
echo "Run sip.lua in Kraken now."
until sipp -sn uac -i "$HOST" -p 5061 -m 1 -nostdin -timeout 15s -timeout_error "$KRAKEN:5060" > "$DIR/uac.txt" 2>&1; do sleep 1; done
echo "SIPp client call to Kraken: OK"
if wait $SERVER; then echo "SIPp server call from Kraken: OK"; else echo "SIPp server call from Kraken: WRONG"; cat "$DIR/uas.txt"; fi
echo "done"
