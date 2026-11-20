import sys
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kavach_protection_agent as protect  # noqa: E402


class ProtectionParserTests(unittest.TestCase):
    def test_lsof_listeners_skip_loopback_and_dedupe(self):
        output = """COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
sshd 101 root 3u IPv4 0x1 0t0 TCP *:22 (LISTEN)
ControlCe 202 bnb 10u IPv6 0x2 0t0 TCP *:7000 (LISTEN)
python3 303 bnb 5u IPv4 0x3 0t0 TCP 127.0.0.1:8789 (LISTEN)
ControlCe 202 bnb 11u IPv6 0x4 0t0 TCP *:7000 (LISTEN)
"""
        rows = protect.parse_lsof_listeners(output)
        self.assertEqual([(row["port"], row["process"]) for row in rows], [(22, "sshd"), (7000, "ControlCe")])

    def test_ss_listeners(self):
        output = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      4096   0.0.0.0:22          0.0.0.0:*    users:(("sshd",pid=101,fd=3))
LISTEN 0      4096   127.0.0.1:8789      0.0.0.0:*    users:(("python3",pid=303,fd=5))
LISTEN 0      4096   [::]:443            [::]:*       users:(("nginx",pid=404,fd=6))
"""
        rows = protect.parse_ss_listeners(output)
        self.assertEqual([(row["port"], row["process"]) for row in rows], [(22, "sshd"), (443, "nginx")])

    def test_slug(self):
        self.assertEqual(protect.slug("WS-PRIYA.local"), "ws-priya.local")
        self.assertEqual(protect.slug("  "), "host")


class ProtectionSnapshotTests(unittest.TestCase):
    def args(self, **overrides):
        base = {
            "output": "",
            "asset_id": "",
            "asset_name": "LAB-01",
            "criticality": "high",
            "owner": "Operations",
            "site": "HQ",
            "environment": "production",
            "exposure": "internal",
            "organization": "Test Org",
            "check_updates": False,
            "no_listeners": False,
            "no_logins": False,
        }
        base.update(overrides)
        return Namespace(**base)

    def test_snapshot_shape_and_unknown_patch_state(self):
        host = {
            "hostname": "lab-host", "os_name": "Ubuntu 24.04", "os_version": "24.04",
        }
        inv = {"software": [{"name": "openssl", "status": "current"}], "patches": {"available": []}}
        with patch.object(protect.inventory, "host_facts", return_value=host), \
             patch.object(protect.inventory, "scan", return_value=inv), \
             patch.object(protect, "disk_encryption", return_value=(True, "LUKS volume present")), \
             patch.object(protect, "firewall", return_value=(True, "ufw is active")), \
             patch.object(protect, "edr_status", return_value=(True, "EDR process observed")), \
             patch.object(protect, "admin_rights", return_value=(False, "Not an administrator")), \
             patch.object(protect, "listening_services", return_value=([{"port": 22, "proto": "tcp", "process": "sshd", "address": "*"}], [])), \
             patch.object(protect, "local_admin_accounts", return_value=(["opsadmin"], "")), \
             patch.object(protect, "current_user", return_value="opsuser"):
            snapshot = protect.build_snapshot(self.args())
        self.assertEqual(snapshot["schema"], "kavach.protection.v1")
        self.assertEqual(snapshot["organization"], "Test Org")
        self.assertEqual(snapshot["assets"][0]["id"], "lab-01")
        self.assertEqual(snapshot["assets"][0]["controls"]["patching"], None)
        self.assertEqual(snapshot["devices"][0]["patch_status"], "unknown")
        self.assertEqual(snapshot["resources"][0]["internet_facing"], None)
        self.assertEqual(len(snapshot["resources"]), 1)
        self.assertEqual(snapshot["logins"][0]["account"], "opsadmin")
        self.assertTrue(any("patching" in note.lower() or "patch status" in note.lower() for note in snapshot["notes"]))

    def test_snapshot_current_and_outdated_patch_states(self):
        host = {"hostname": "lab-host", "os_name": "Ubuntu 24.04", "os_version": "24.04"}
        with patch.object(protect.inventory, "host_facts", return_value=host), \
             patch.object(protect.inventory, "scan", return_value={"software": [{"name": "openssl", "status": "current"}], "patches": {"available": []}}), \
             patch.object(protect, "disk_encryption", return_value=(True, "ok")), \
             patch.object(protect, "firewall", return_value=(True, "ok")), \
             patch.object(protect, "edr_status", return_value=(True, "ok")), \
             patch.object(protect, "admin_rights", return_value=(False, "ok")), \
             patch.object(protect, "listening_services", return_value=([], [])), \
             patch.object(protect, "local_admin_accounts", return_value=([], "")), \
             patch.object(protect, "current_user", return_value="opsuser"):
            current = protect.build_snapshot(self.args(check_updates=True))
        self.assertEqual(current["devices"][0]["patch_status"], "current")
        self.assertEqual(current["assets"][0]["controls"]["patching"], True)

        with patch.object(protect.inventory, "host_facts", return_value=host), \
             patch.object(protect.inventory, "scan", return_value={"software": [{"name": "openssl", "status": "outdated"}], "patches": {"available": [{"id": "openssl"}]}}), \
             patch.object(protect, "disk_encryption", return_value=(True, "ok")), \
             patch.object(protect, "firewall", return_value=(True, "ok")), \
             patch.object(protect, "edr_status", return_value=(True, "ok")), \
             patch.object(protect, "admin_rights", return_value=(False, "ok")), \
             patch.object(protect, "listening_services", return_value=([], [])), \
             patch.object(protect, "local_admin_accounts", return_value=([], "")), \
             patch.object(protect, "current_user", return_value="opsuser"):
            outdated = protect.build_snapshot(self.args(check_updates=True))
        self.assertEqual(outdated["devices"][0]["patch_status"], "outdated")
        self.assertEqual(outdated["assets"][0]["controls"]["patching"], False)

    def test_no_listener_and_no_login_flags(self):
        host = {"hostname": "lab-host", "os_name": "Ubuntu 24.04", "os_version": "24.04"}
        with patch.object(protect.inventory, "host_facts", return_value=host), \
             patch.object(protect.inventory, "scan", return_value={"software": [], "patches": {"available": []}}), \
             patch.object(protect, "disk_encryption", return_value=(None, "unknown")), \
             patch.object(protect, "firewall", return_value=(None, "unknown")), \
             patch.object(protect, "edr_status", return_value=(None, "unknown")), \
             patch.object(protect, "admin_rights", return_value=(None, "unknown")), \
             patch.object(protect, "listening_services", return_value=([], [])), \
             patch.object(protect, "local_admin_accounts", return_value=([], "")), \
             patch.object(protect, "current_user", return_value="opsuser"):
            snapshot = protect.build_snapshot(self.args(no_listeners=True, no_logins=True))
        self.assertEqual(snapshot["resources"], [])
        self.assertEqual(snapshot["logins"], [])
        self.assertTrue(any("skipped" in note.lower() for note in snapshot["notes"]))


if __name__ == "__main__":
    unittest.main()
