# SMB and DCERPC Experiment

This runs one Kraken global Lua script against a Windows 10 machine to exercise
`protocols/smb` and `protocols/dcerpc`:

- SMB files: create a unique directory in a test share, then write, read at
  offsets, stat, list, rename and remove binary data, including a 32 KiB block
  and an empty read at end of file.
- DCERPC over SMB: authenticated, signed `srvsvc` bind and `NetrShareEnum`,
  which must list the test share, then `NetrRemoteTOD` as a raw stub on the
  `srvsvc` pipe by interface UUID.
- DCERPC over TCP: bind the endpoint mapper on port `135`, check its `Lookup`
  request template, call `Lookup` by name (YAML in, Lua table out) and check the
  endpoint tower, then repeat the call as a raw NDR stub on an interface UUID
  and opnum.

You need a reachable Windows 10 machine and a **local account with a password**
(not a PIN). In an elevated PowerShell window for that account, create a
disposable share and note the computer name and IP address:

```powershell
$probePath = Join-Path $env:PUBLIC 'KrakenProbe'
New-Item -ItemType Directory -Path $probePath -Force
New-SmbShare -Name KrakenProbe -Path $probePath -FullAccess (whoami)
hostname
ipconfig
```

If the share already exists, inspect it; do not overwrite it. Make the network
profile Private and enable File and Printer Sharing. Kraken must reach the
Windows IP on TCP `445` and `135`. If a firewall rule is needed, scope it to the
Kraken identity's IP rather than disabling the firewall:

```powershell
$krakenIp = '192.168.122.5' # the Kraken identity IP
New-NetFirewallRule -DisplayName 'Kraken probe SMB' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -Profile Private -RemoteAddress $krakenIp
New-NetFirewallRule -DisplayName 'Kraken probe RPC' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 135 -Profile Private -RemoteAddress $krakenIp
```

Set up the identity as in the [socket experiment](../socket/README.md),
including the `forward.lua` transport, and start it.

In Kraken, copy `smb_dcerpc.lua` into a global script. Edit the five values at
the top: identity, Windows IPv4 address, computer name, local username and
password. Do not save or share a script containing a real password. Run it.

Success prints `PASS` lines for each stage and ends with
`smb dcerpc experiment passed`. A failure names the stage and stops the run; fix
it and run the same script again. The SMB stage cleans up after itself on
failure; if the error says a directory remains, inspect it in the share.

The TCP stage calls `Lookup` on the endpoint mapper, not `srvsvc` on a dynamic
port. Windows may require RPC authentication under enterprise policy; direct
TCP has none.

When finished, remove the two firewall rules **if you created them**:

```powershell
Remove-NetFirewallRule -DisplayName 'Kraken probe SMB', 'Kraken probe RPC'
```
