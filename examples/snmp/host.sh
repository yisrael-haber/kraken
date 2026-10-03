#!/bin/sh
# The host's end of the SNMP experiment, with net-snmp, the standard implementation:
#   sudo sh examples/snmp/host.sh
# It runs snmpd (an agent) on 192.168.122.1:161 and snmptrapd on :162, then, once Kraken's
# script is running its own agent, queries it with snmpget, snmpgetnext and snmpbulkget.
# Ports 161 and 162 need root. Needs net-snmp: sudo apt install snmpd snmptrapd snmp
set -e

HOST=192.168.122.1
KRAKEN=192.168.122.5
DIR=/tmp/kraken-snmp

if [ "$(id -u)" != 0 ]; then echo "run it with sudo: ports 161 and 162 need root"; exit 1; fi
for tool in snmpd snmptrapd snmpget snmpgetnext snmpbulkget; do
    if ! command -v "$tool" > /dev/null; then echo "$tool not found: sudo apt install snmpd snmptrapd snmp"; exit 1; fi
done

# Debian starts its own snmpd and snmptrapd (socket-activated) services on install, and ships no MIB files:
# stop the services to free the ports, and load no MIBs (the output stays numeric anyway).
systemctl stop snmptrapd.socket snmptrapd snmpd 2> /dev/null || true
export MIBS=

rm -rf "$DIR"
mkdir -p "$DIR"
cat > "$DIR/snmpd.conf" <<CONF
agentaddress udp:$HOST:161
rocommunity public
sysName kraken-lab-host
sysLocation Kraken lab
sysContact lab@example.test
CONF
cat > "$DIR/snmptrapd.conf" <<CONF
disableAuthorization yes
CONF

snmpd -f -Lo -C -c "$DIR/snmpd.conf" &
AGENT=$!
snmptrapd -f -Lo -C -c "$DIR/snmptrapd.conf" "udp:$HOST:162" &
TRAPS=$!
trap 'kill $AGENT $TRAPS 2> /dev/null' EXIT INT TERM

echo "snmpd on $HOST:161 (community public) and snmptrapd on $HOST:162; waiting for Kraken's agent on $KRAKEN:161 ..."
echo "Run snmp.lua in Kraken now. Traps it sends are printed above by snmptrapd."
until snmpget -v2c -c public -t 1 -r 0 -On "$KRAKEN:161" 1.3.6.1.2.1.1.1.0 > "$DIR/probe.txt" 2> /dev/null; do sleep 1; done

check() {   # check "what" "command output" "text it must contain"
    if printf '%s\n' "$2" | grep -q -F "$3"; then echo "$1: OK"; else echo "$1: WRONG"; printf '%s\n' "$2"; fi
}
check "snmpget sysDescr from Kraken" "$(cat "$DIR/probe.txt")" "Kraken scripted device"
check "snmpgetnext from sysDescr" "$(snmpgetnext -v2c -c public -On "$KRAKEN:161" 1.3.6.1.2.1.1.1.0)" "kraken-lab"
bulk=$(snmpbulkget -v2c -c public -On -Cn0 -Cr4 "$KRAKEN:161" 1.3.6.1.2.1.1)
check "snmpbulkget over the system group" "$bulk" "No more variables left"
printf '%s\n' "$bulk"
echo "done; stopping snmpd and snmptrapd"
