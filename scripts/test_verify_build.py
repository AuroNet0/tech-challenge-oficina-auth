import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from verify_build import findings, metrics, scan_jar, write_test_summary


def archive(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as output:
        for name, content in entries.items():
            output.writestr(name, content)
    return buffer.getvalue()


class VerificationTest(unittest.TestCase):
    def test_nested_private_fixture_is_blocked(self):
        payload = b"-----BEGIN " + b"PRIVATE KEY-----\n" + b"A" * 64
        nested = archive({"example.class": payload})
        result = scan_jar(archive({"BOOT-INF/lib/dependency.jar": nested}))
        self.assertEqual(result[0]["member"], "BOOT-INF/lib/dependency.jar!example.class")
        self.assertNotIn("payload", result[0])

    def test_marker_without_body_is_not_key(self):
        self.assertEqual(findings("type.class", b"-----BEGIN " + b"PRIVATE KEY-----"), [])

    def test_forbidden_filename(self):
        self.assertTrue(findings(".env", b"anything"))

    def test_unsafe_archive(self):
        with self.assertRaises(ValueError):
            scan_jar(archive({"../outside": b"content"}))

    def test_missing_reports_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                metrics(Path(folder))

    def test_failed_test_summary_is_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            reports = root / "target/surefire-reports"
            reports.mkdir(parents=True)
            (reports / "TEST-example.xml").write_text('<testsuite tests="1" failures="1"/>')
            summary = write_test_summary(root)
            self.assertEqual(summary["state"], "diagnostic_only")
            self.assertEqual(summary["tests"]["failures"], 1)
            self.assertNotIn("approved", summary)

    def test_coverage_and_skips(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            reports = root / "target/surefire-reports"
            reports.mkdir(parents=True)
            jacoco = root / "target/site/jacoco"
            jacoco.mkdir(parents=True)
            (reports / "TEST-example.xml").write_text('<testsuite tests="1" failures="0" errors="0" skipped="0"/>')
            (jacoco / "jacoco.xml").write_text('<report><counter type="LINE" covered="80" missed="20"/></report>')
            self.assertEqual(metrics(root)["line_covered"], 80)
            (reports / "TEST-example.xml").write_text('<testsuite tests="1" skipped="1"/>')
            with self.assertRaises(ValueError):
                metrics(root)
            (reports / "TEST-example.xml").write_text('<testsuite tests="1"/>')
            (jacoco / "jacoco.xml").write_text('<report><counter type="LINE" covered="79" missed="21"/></report>')
            with self.assertRaises(ValueError):
                metrics(root)


if __name__ == "__main__":
    unittest.main()
