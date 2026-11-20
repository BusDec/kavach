# Kavach Network watch — local capture agent

Metadata-only traffic observation for an authorized network. The agent uses
`tcpdump` to read packet headers on one interface, aggregates them into flows
and serves the same dashboard that lives at `/network/`.

**It does not capture payloads, credentials or application content.** It does
not modify, inject or block traffic.

## Requirements

- Python 3.10+
- `tcpdump` (macOS ships it at `/usr/sbin/tcpdump`)
- Root privileges for packet capture
- Written authorization to monitor the network and a lawful basis for any
  personal data in the metadata

## Run

From the Kavach repository:

```bash
sudo python3 agent/kavach_network_agent.py --interface en0
```

Then open:

```text
http://127.0.0.1:8787/
```

On macOS, confirm the Wi-Fi interface with
`networksetup -listallhardwareports`; it is often `en0` or `en1`. The agent sees
the traffic visible to that host. Capturing other devices requires a TAP, SPAN
or an authorized monitor-mode deployment; a browser page cannot do that.

Options:

```bash
--interface en0          # capture interface
--bpf "ip or ip6"        # tcpdump filter
--port 8787              # dashboard port
```

## Analyze an existing capture

You do not need the agent to inspect a file that already exists. Open
`/network/`, choose **Choose a capture**, and select a `.pcap` or `.pcapng`
from tcpdump, Wireshark, a SPAN/TAP or an authorized Wi-Fi monitor. The file is
parsed in the browser tab, aggregated into 5-tuple conversations, and never
uploaded. This works for classic pcap, pcapng, raw IP, Linux SLL, Ethernet and
802.11/radiotap captures.

To record a file on the host you are authorized to monitor:

```bash
sudo tcpdump -i en0 -s 96 -w kavach-capture.pcap
```

Stop with `Ctrl-C`, then drop the file into `/network/`.

## Windows packet capture

The Python agent uses `tcpdump`, which is not the normal Windows capture path.
Use the built-in `pktmon` instead, in an Administrator PowerShell:

```powershell
pktmon start --capture --pkt-size 96 --file-name C:\temp\kavach.etl
# reproduce the activity, then:
pktmon stop
pktmon etl2pcap C:\temp\kavach.etl --out C:\temp\kavach.pcapng
```

Drop `kavach.pcapng` into `/network/`. To restrict the capture, add a filter
before starting:

```powershell
pktmon filter add -i 10.20.4.15
pktmon filter add -p 443
```

`pktmon filter remove` clears filters. `pktmon` works on Windows 10/11 and
Windows Server 2019+. For a Wireshark/Npcap install, use
`dumpcap -D` to list interfaces and then
`dumpcap -i 1 -s 96 -w C:\temp\kavach.pcapng`.

A Windows capture sees only that machine's networking stack. For another
machine, run the capture on that endpoint, use a SPAN/TAP, or deploy an
authorized agent. The browser importer supports the resulting pcapng file.

To collect from several Windows endpoints with PowerShell Remoting:

```powershell
$hosts = @("WIN01", "WIN02")
Invoke-Command -ComputerName $hosts -ScriptBlock {
  $etl  = "$env:WINDIR\Temp\kavach.etl"
  $pcap = "$env:WINDIR\Temp\kavach.pcapng"
  pktmon start --capture --pkt-size 96 --file-name $etl
  Start-Sleep -Seconds 300
  pktmon stop
  pktmon etl2pcap $etl --out $pcap
}
foreach ($hostName in $hosts) {
  Copy-Item "\\$hostName\C$\Windows\Temp\kavach.pcapng" ".\$hostName.pcapng"
}
```

Use an account with the required WinRM and local administrator rights, and
capture only hosts you are authorized to monitor. Adjust the duration and
`pktmon filter` to keep the capture small.

## What it classifies

- Direction: inbound, outbound or transit, relative to the local interface
- Host: remote IP, bytes in/out, applications and last seen
- Application: inferred from the destination or source port (SAP HTTPS, DNS,
  SSH, SMB, MQTT, Modbus/TCP, IEC 60870-5-104, BACnet, etc.)
- Protocol: TCP, UDP, ICMP, TLS, DNS or the OT protocol name
- Risk flags: cleartext protocol, OT protocol observed, unknown public host,
  transit traffic, new host

## Limits

- Port-based classification is a heuristic; it does not decrypt TLS or inspect
  application payloads.
- A switched Wi-Fi network does not deliver other clients' unicast traffic to
  this host. Use an authorized sensor, TAP or SPAN for network-wide visibility.
- The agent stores flows in memory only; restarting clears the view.
- The critical-asset watchlist is browser-local. It flags live metadata while
  the dashboard is open, but the agent does not persist the list or send alerts
  when no dashboard is connected.
- Do not run it on a network you do not own or have explicit permission to
  monitor. Follow the privacy rules that apply to you (for example DPDP, GDPR
  or US state law).
