# One SMB/DCERPC probe

Run `probe.lua` once as a Kraken global script. It tests independent SMB file
operations, DCERPC over SMB, and DCERPC over TCP. You need a reachable Windows
10 machine and a Kraken identity; there are no other probe scripts to juggle.

On Windows, use a **local account with a password** (not a PIN). In an elevated
PowerShell window for that same account, create a disposable share:

```powershell
$probePath = Join-Path $env:PUBLIC 'KrakenProbe'
New-Item -ItemType Directory -Path $probePath -Force
New-SmbShare -Name KrakenProbe -Path $probePath -FullAccess (whoami)
hostname
ipconfig
```

If that share already exists, inspect it; do not overwrite it. Make the network
profile Private and enable File and Printer Sharing. Kraken must reach the
Windows IP on TCP 445 and 135. If a firewall rule is needed, scope it to the
Kraken identity's IP rather than disabling the firewall:

```powershell
$krakenIp = '192.0.2.10' # replace with the Kraken identity IP
New-NetFirewallRule -DisplayName 'Kraken probe SMB' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -Profile Private -RemoteAddress $krakenIp
New-NetFirewallRule -DisplayName 'Kraken probe RPC' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 135 -Profile Private -RemoteAddress $krakenIp
```

Start the Kraken identity (and its normal forwarding transport, if configured).
Edit the five values at the top of `probe.lua`: identity, Windows IPv4 address,
computer name, local username, and password. Run the entire script. It prints
four `PASS` lines. A failure names the stage and stops the run; fix it and
rerun this same script. The SMB stage uses a unique directory inside the test
share and attempts cleanup on failure. Inspect that directory if the error
reports it remains. Do not save or share a script containing a real password.

The TCP stage calls `Lookup` on the endpoint mapper at port 135, not `srvsvc`
on a dynamic port. Windows may require RPC authentication under enterprise
policy; this client does not implement that yet. The build/unit tests cannot
replace this live run.

When finished, remove the two firewall rules **if you created them**:

```powershell
Remove-NetFirewallRule -DisplayName 'Kraken probe SMB', 'Kraken probe RPC'
```

References: [Windows RPC firewall guidance](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/best-practices-configuring), [endpoint mapper `Lookup`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab744583-430e-4055-8901-3c6bc007e791), [New-SmbShare](https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbshare), [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule).
