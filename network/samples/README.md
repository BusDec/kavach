# Synthetic sample capture

`kavach-sample.pcap` is a synthetic Ethernet capture made for trying the
Network watch importer. All addresses are documentation or private ranges and
there is no real traffic, payload or personal data in the file.

Use **Try a synthetic sample** on `/network/`, or drop the file into the page
yourself. Expected result: 58 packets, 20 aggregated flows, TLS, DNS, Modbus/TCP, MQTT,
IEC 60870-5-104, SMB, SSH, HTTP, ICMP and a small amount of transit traffic.

To make a real capture on a network you are authorized to monitor:

```bash
sudo tcpdump -i en0 -s 96 -w kavach-capture.pcap
```

Stop with `Ctrl-C`, then drop `kavach-capture.pcap` into `/network/`. The file
is parsed in the browser tab and is never uploaded.
