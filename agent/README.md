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

On macOS, `en0` is usually Wi-Fi. The agent sees the traffic visible to that
host. Capturing other devices requires a TAP, SPAN or an authorized
monitor-mode deployment; a browser page cannot do that.

Options:

```bash
--interface en0          # capture interface
--bpf "ip or ip6"        # tcpdump filter
--port 8787              # dashboard port
```

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
- Do not run it on a network you do not own or have explicit permission to
  monitor. Follow the privacy rules that apply to you (for example DPDP, GDPR
  or US state law).
