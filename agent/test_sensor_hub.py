import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kavach_inventory_agent as invmod  # noqa: E402
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


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.baseline = hubmod.Baseline({
            "software": [{"name": "OpenSSL", "minimum_version": "3.0.16"}],
            "required_patches": {"linux": ["USN-7000-1"]},
            "minimum_build": {"linux": "24.04"},
        })
        self.store = hubmod.InventoryStore(self.baseline, hubmod.Assets(use_defaults=True))

    def snapshot(self, **overrides):
        data = {
            "hostname": "LINUX-JUMP", "os_family": "linux", "os_name": "Ubuntu 24.04 LTS",
            "os_version": "24.04", "ip_addresses": ["10.20.4.12"], "last_scan": 1773306600.0,
            "software": [
                {"name": "OpenSSL", "version": "3.0.13", "latest": "3.0.16", "latest_source": "apt"},
                {"name": "nginx", "version": "1.24.0", "latest": "1.24.0"},
            ],
            "patches": {"installed": [], "available": [], "missing": []},
            "reboot_pending": False,
        }
        data.update(overrides)
        return data

    def test_version_comparison(self):
        self.assertTrue(hubmod.version_less("3.0.9", "3.0.16"))
        self.assertFalse(hubmod.version_less("3.0.16", "3.0.16"))
        self.assertTrue(hubmod.version_less("17.0.11", "17.0.12"))
        self.assertTrue(hubmod.version_less("19045.5487", "19045.5488"))
        self.assertFalse(hubmod.version_less("", "1.0"))

    def test_outdated_and_missing_baseline_patch(self):
        host = self.store.upsert(self.snapshot())
        self.assertEqual(host["outdated_count"], 1)
        self.assertEqual(host["software"][0]["status"], "outdated")
        self.assertEqual(host["software"][0]["update_source"], "baseline")
        self.assertEqual(host["software"][1]["status"], "current")
        self.assertEqual(host["missing_patch_count"], 1)
        self.assertEqual(host["patches"]["missing"][0]["id"], "USN-7000-1")
        self.assertEqual(host["risk"], "medium")
        self.assertEqual(host["gap_count"], 2)

    def test_installed_patch_clears_gap(self):
        host = self.store.upsert(self.snapshot(patches={
            "installed": [{"id": "USN-7000-1", "title": "OpenSSL update"}],
            "available": [], "missing": [],
        }))
        self.assertEqual(host["missing_patch_count"], 0)
        self.assertEqual(host["patches"]["missing"], [])

    def test_scan_count_increments(self):
        self.store.upsert(self.snapshot())
        host = self.store.upsert(self.snapshot())
        self.assertEqual(host["scan_count"], 2)

    def test_critical_asset_raises_risk(self):
        host = self.store.upsert(self.snapshot(
            hostname="OT-HISTORIAN", ip_addresses=["10.30.7.50"], last_scan=1773306600.0,
        ))
        self.assertTrue(host["critical_asset"])
        self.assertEqual(host["risk"], "high")
        self.assertEqual(self.store.summary()["criticalGaps"], 1)

    def test_software_search_and_export(self):
        self.store.upsert(self.snapshot())
        rows = self.store.software("openssl")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["hostname"], "LINUX-JUMP")
        self.assertEqual(rows[0]["status"], "outdated")
        csv_text = self.store.csv_text()
        self.assertIn("LINUX-JUMP", csv_text)
        self.assertIn("OpenSSL", csv_text)
        self.assertIn("USN-7000-1", csv_text)

    def test_patch_gaps_listing(self):
        self.store.upsert(self.snapshot())
        gaps = self.store.patch_gaps()
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["hostname"], "LINUX-JUMP")
        self.assertEqual(gaps[0]["minimum_build"], "24.04")

    def test_inventory_demo_seed(self):
        hub = hubmod.Hub(hubmod.Assets(use_defaults=True), baseline=hubmod.Baseline(use_defaults=True))
        hubmod.seed_inventory_demo(hub.inventory)
        summary = hub.inventory.summary()
        self.assertEqual(summary["hosts"], 5)
        self.assertGreater(summary["software"], 15)
        self.assertGreater(summary["outdated"], 5)
        self.assertEqual(summary["criticalHosts"], 2)
        self.assertEqual(summary["criticalGaps"], 2)
        names = {row["hostname"] for row in hub.inventory.host_rows()}
        self.assertEqual(names, {"WS-PRIYA", "APP-SAP01", "MBP-DESIGN", "LINUX-JUMP", "OT-HISTORIAN"})


class InventoryCollectorTests(unittest.TestCase):
    def test_dpkg_and_rpm_parsing(self):
        dpkg = invmod.parse_dpkg(
            "openssl\t3.0.13-0ubuntu1.3\tUbuntu Developers\nnginx\t1.24.0-2ubuntu7\tUbuntu\n"
        )
        self.assertEqual([row["name"] for row in dpkg], ["openssl", "nginx"])
        self.assertEqual(dpkg[0]["version"], "3.0.13-0ubuntu1.3")
        self.assertEqual(dpkg[0]["source"], "dpkg")

        rpm = invmod.parse_rpm("openssl\t3.0.7-27.el9\tRed Hat, Inc.\t1700000000\n")
        self.assertEqual(rpm[0]["version"], "3.0.7-27.el9")
        self.assertTrue(rpm[0]["install_date"].startswith("2023-"))

    def test_apk_parsing_strips_version(self):
        rows = invmod.parse_apk("py3-cryptography-42.0.8-r0\nmusl-1.2.4-r2\n")
        self.assertEqual(rows[0]["name"], "py3-cryptography")
        self.assertEqual(rows[0]["version"], "42.0.8-r0")
        self.assertEqual(rows[1]["name"], "musl")

    def test_apt_upgradable_parsing(self):
        latest, patches = invmod.parse_apt_upgradable(
            "libssl3/noble-updates 3.0.13-0ubuntu1.4 amd64 [upgradable from: 3.0.13-0ubuntu1.3]\n"
        )
        self.assertEqual(latest["libssl3"], "3.0.13-0ubuntu1.4")
        self.assertEqual(patches[0]["id"], "libssl3")
        self.assertIn("3.0.13-0ubuntu1.3", patches[0]["title"])

    def test_brew_outdated_parsing(self):
        latest = invmod.parse_brew_outdated({
            "formulae": [{"name": "openssl@3", "current_version": "3.4.0"}],
            "casks": [{"token": "zed", "current_version": "0.170.2"}],
        })
        self.assertEqual(latest["openssl@3"], "3.4.0")
        self.assertEqual(latest["zed"], "0.170.2")

    def test_snapshot_post_payload_shape(self):
        snapshot = {
            "hostname": "TEST-HOST", "os_family": "linux", "os_name": "Ubuntu 24.04",
            "os_version": "24.04", "software": [], "patches": {"installed": [], "available": [], "missing": []},
        }
        store = hubmod.InventoryStore(hubmod.Baseline(), hubmod.Assets())
        host = store.upsert(snapshot)
        self.assertEqual(host["id"], "test-host")
        self.assertEqual(host["scan_count"], 1)
        self.assertEqual(host["risk"], "low")


if __name__ == "__main__":
    unittest.main()
