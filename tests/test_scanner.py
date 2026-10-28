import io
import json
import threading
import unittest
import xml.etree.ElementTree as ET
import zipfile
from unittest.mock import patch
from urllib.request import Request, urlopen

import server


class RuleScannerTests(unittest.TestCase):
    def test_flags_multiple_malware_indicators(self):
        findings = server.analyze_text(
            """# suspicious sample
powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAA
https://discord.com/api/webhooks/123456789012/abcdefghijklmnopqrstuvwxyz
stratum+tcp://pool.example:3333
""",
            "scripts/check.ps1",
        )
        self.assertEqual(
            {"encoded-powershell", "discord-webhook", "crypto-miner"},
            {finding["id"] for finding in findings},
        )
        self.assertTrue(all(finding["path"] == "scripts/check.ps1" for finding in findings))

    def test_redacts_webhook_token_from_evidence(self):
        finding = server.analyze_text(
            "const endpoint = 'https://discord.com/api/webhooks/123456789012/abcdefghijklmnopqrstuvwxyz';"
        )[0]
        self.assertIn("[REDACTED]", finding["evidence"])
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", finding["evidence"])
        self.assertNotIn("my_private_token_123", server._redact_evidence('ACCESS_TOKEN = "my_private_token_123"'))

    def test_score_is_bounded_and_explained(self):
        report = server.scan_code("VirtualAllocEx(handle, 0, 100, 0, 0);", "sample.cpp")
        self.assertEqual(45, report["summary"]["risk_score"])
        self.assertEqual("High", report["summary"]["risk_label"])
        self.assertEqual(["sample.cpp"], report["scanned_files"])
        self.assertEqual("critical", report["findings"][0]["severity"])
        self.assertTrue(report["findings"][0]["behavior"])
        self.assertTrue(report["findings"][0]["install_effect"])

    def test_rules_are_shared_with_the_pages_scanner(self):
        ruleset = json.loads((server.WEB_ROOT / "rules.json").read_text(encoding="utf-8"))
        self.assertEqual(len(server.RULES), len(ruleset["rules"]))
        self.assertEqual(server.MAX_FILES_PER_REPO_SCAN, ruleset["maxFiles"])
        self.assertTrue(all(rule.get("behavior") and rule.get("install_effect") for rule in ruleset["rules"]))

    def test_windows_sandbox_profile_is_offline_and_has_no_startup_command(self):
        profile = ET.parse(server.WEB_ROOT / "windows-11-offline-sandbox.wsb").getroot()
        settings = {item.tag: item.text for item in profile}
        self.assertEqual("Configuration", profile.tag)
        self.assertEqual("Disable", settings.get("Networking"))
        self.assertEqual("Disable", settings.get("ClipboardRedirection"))
        self.assertEqual("Disable", settings.get("VGpu"))
        self.assertEqual("Enable", settings.get("ProtectedClient"))
        self.assertNotIn("MappedFolders", settings)
        self.assertNotIn("LogonCommand", settings)

    def test_empty_paste_is_rejected(self):
        with self.assertRaises(server.ScanError):
            server.scan_code("  ")

    def test_suspicious_filename_is_only_a_low_confidence_indicator(self):
        report = server.scan_code("ordinary text", "downloads/possible-trojan.ps1")
        finding = next(item for item in report["findings"] if item["id"] == "suspicious-filename")
        self.assertEqual("low", finding["severity"])
        self.assertEqual("possible-trojan.ps1", finding["evidence"].split(": ", 1)[1])


class GithubInputTests(unittest.TestCase):
    def test_accepts_repository_shorthand_and_tree_links(self):
        self.assertEqual(
            ("octocat", "hello-world", None),
            server.parse_github_repository("octocat/hello-world"),
        )
        self.assertEqual(
            ("octocat", "hello-world", "main"),
            server.parse_github_repository("https://github.com/octocat/hello-world/tree/main/src"),
        )
        self.assertEqual(
            ("octocat", "hello-world", "release/2026"),
            server.parse_github_repository("https://github.com/octocat/hello-world", "release/2026"),
        )

    def test_rejects_non_github_hosts_and_invalid_paths(self):
        for value in (
            "https://example.com/octocat/hello-world",
            "http://github.com/octocat/hello-world",
            "https://github.com.evil.test/octocat/hello-world",
            "https://github.com/octocat",
            "https://github.com/octocat/hello-world/issues/1",
        ):
            with self.subTest(value=value), self.assertRaises(server.ScanError):
                server.parse_github_repository(value)

    def test_repository_scan_reads_a_bounded_archive_without_extracting(self):
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("sample-main/README.md", "A small demonstration repository.")
            archive.writestr("sample-main/src/miner.py", "pool = 'stratum+tcp://pool.invalid:3333'\n")
            archive.writestr("sample-main/trojan.ps1", "Write-Host 'review me'\n")
            archive.writestr("sample-main/trojan.exe", b"\x00\x01\x02")
        progress = []
        metadata = {
            "default_branch": "main",
            "full_name": "owner/sample",
            "html_url": "https://github.com/owner/sample",
        }
        with patch.object(server, "_github_json", return_value=metadata), patch.object(
            server, "_download_archive", return_value=archive_buffer.getvalue()
        ):
            report = server.scan_github_repository("https://github.com/owner/sample", progress=progress.append)

        self.assertEqual("owner/sample", report["repository"]["full_name"])
        self.assertIn("src/miner.py", report["scanned_files"])
        self.assertIn("crypto-miner", {item["id"] for item in report["findings"]})
        self.assertIn("suspicious-filename", {item["id"] for item in report["findings"]})
        self.assertEqual(1, report["scan_limits"]["skip_counts"]["binary_files"])
        self.assertTrue(any(event.get("total") == 4 for event in progress))


class HTTPIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.ScannerHTTPServer(("127.0.0.1", 0), server.RequestHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def test_health_endpoint_reports_static_only_mode(self):
        with urlopen(self.base_url + "/api/health", timeout=3) as response:
            payload = json.loads(response.read())
        self.assertEqual("ok", payload["status"])
        self.assertFalse(payload["vm_sandbox"]["execution_enabled"])

    def test_paste_endpoint_streams_progress_and_report(self):
        body = json.dumps({"filename": "review.py", "code": "print('hello')"}).encode()
        request = Request(
            self.base_url + "/api/scan/code",
            data=body,
            headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            result = response.read().decode()
        self.assertIn("event: progress", result)
        self.assertIn("event: result", result)
        self.assertIn('"files_scanned": 1', result)
        self.assertIn('"risk_label": "No indicators"', result)


if __name__ == "__main__":
    unittest.main()
