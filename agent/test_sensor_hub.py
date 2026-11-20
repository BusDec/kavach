import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kavach_sensor_hub as hubmod  # noqa: E402


class SensorHubTests(unittest.TestCase):
    def setUp(self):
        self.hub = hubmod.Hub(hubmod.Assets(use_defaults=True))

    def test_zeek_conn_dns_and_tls(self):
        sensor = hubmod.ZeekSensor(self.hub, "/tmp/unused-zeek-dir")
        path = Path("conn.log")
        conn = sensor.normalize({
            "ts": 1773306600.0, "_path": "conn", "uid": "C1",
            "id": {"orig_h": "10.0.0.5", "orig_p": 51544, "resp_h": "10.20.4.15", "resp_p": 443},
            "proto": "tcp", "service": "ssl", "orig_bytes": 300, "resp_bytes": 900,
        }, path)
        self.assertEqual(conn["kind"], "flow")
        self.assertEqual(conn["dst_ip"], "10.20.4.15")
        self.assertEqual(conn["dst_port"], 443)
        self.assertEqual(conn["bytes_out"], 300)

        dns = sensor.normalize({
            "ts": 1773306600.0, "_path": "dns", "uid": "D1",
            "id": {"orig_h": "10.0.0.5", "orig_p": 53000, "resp_h": "10.0.0.1", "resp_p": 53},
            "query": "update-check.example", "answers": ["45.33.32.156"], "rcode_name": "NOERROR",
        }, Path("dns.log"))
        self.assertEqual(dns["domain"], "update-check.example")
        self.assertEqual(dns["kind"], "dns")

        tls = sensor.normalize({
            "ts": 1773306600.0, "_path": "ssl", "uid": "S1",
            "id": {"orig_h": "10.0.0.5", "orig_p": 51544, "resp_h": "45.33.32.156", "resp_p": 443},
            "server_name": "update-check.example", "ja3": "abc",
        }, Path("ssl.log"))
        self.assertEqual(tls["kind"], "tls")
        self.assertEqual(tls["domain"], "update-check.example")

    def test_osquery_socket(self):
        sensor = hubmod.OsquerySensor(self.hub, binary="/usr/bin/osqueryi")
        event = sensor.normalize({
            "pid": "7712", "name": "powershell.exe", "username": "priya.n",
            "local_address": "10.20.4.62", "local_port": "51544",
            "remote_address": "45.33.32.156", "remote_port": "443",
            "protocol": "6", "state": "ESTABLISHED",
        }, 1773306600.0)
        self.assertEqual(event["process"], "powershell.exe")
        self.assertEqual(event["dst_ip"], "45.33.32.156")
        self.assertEqual(event["proto"], "tcp")

    def test_wazuh_4625(self):
        sensor = hubmod.WazuhSensor(self.hub, "/tmp/unused-alerts.json")
        event = sensor.normalize({
            "timestamp": "2026-03-12T02:05:00.000+0000",
            "agent": {"name": "WS-PRIYA"},
            "rule": {"id": "60122", "level": 10, "description": "Windows logon failure"},
            "data": {"win": {"system": {"eventID": "4625"}, "eventdata": {"targetUserName": "priya.n", "ipAddress": "45.77.12.34"}}},
        })
        self.assertEqual(event["kind"], "auth")
        self.assertEqual(event["result"], "failure")
        self.assertEqual(event["user"], "priya.n")
        self.assertIn(event["severity"], ("high", "critical"))

    def test_demo_cases_and_entities(self):
        hubmod.seed_demo(self.hub)
        snapshot = self.hub.snapshot()
        self.assertGreaterEqual(snapshot["stats"]["events"], 10)
        titles = {case["title"] for case in snapshot["cases"]}
        self.assertIn("Critical asset access", titles)
        self.assertIn("Password spray across accounts", titles)
        self.assertIn("Lateral movement pattern", titles)
        self.assertIn("Identity and network activity correlate", titles)
        entities = self.hub.search_entities("priya.n")
        self.assertTrue(entities)
        detail = self.hub.entity_detail(entities[0]["id"])
        self.assertTrue(detail["timeline"])
        self.assertGreaterEqual(len(detail["neighbors"]), 1)

    def test_ingest_and_critical_asset(self):
        count = self.hub.ingest([{
            "ts": 1773306600.0, "sensor": "test", "kind": "flow",
            "host": "10.0.0.5", "src_ip": "10.0.0.5", "dst_ip": "10.30.7.40",
            "dst_port": 502, "proto": "tcp", "message": "Modbus",
        }], "test")
        self.assertEqual(count, 1)
        snapshot = self.hub.snapshot()
        self.assertEqual(snapshot["stats"]["criticalAssets"], 3)
        self.assertTrue(any(case["rule"] == "critical-asset-access" for case in snapshot["cases"]))


if __name__ == "__main__":
    unittest.main()
