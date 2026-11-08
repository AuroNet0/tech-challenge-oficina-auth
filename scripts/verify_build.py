import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def findings(name, content):
    patterns = (
        rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\r\n]{32,}",
        rb"(?:AKIA|ASIA)[A-Z0-9]{16}",
        rb"eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}",
    )
    forbidden = PurePosixPath(name).name in {".env", "credentials", "id_rsa", "id_ed25519"}
    if forbidden or any(re.search(pattern, content) for pattern in patterns):
        return [{"member": name, "sha256": sha256(content)}]
    return []


def scan_jar(content, prefix="", budget=None):
    budget = [250 * 1024 * 1024] if budget is None else budget
    result = []
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("duplicate archive entry")
        budget[0] -= sum(entry.file_size for entry in archive.infolist())
        if budget[0] < 0:
            raise ValueError("archive size limit")
        for entry in archive.infolist():
            name = PurePosixPath(entry.filename)
            if stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError("archive symlink rejected")
            if name.is_absolute() or ".." in name.parts or "\\" in entry.filename:
                raise ValueError("unsafe archive path")
            if entry.is_dir():
                continue
            payload = archive.read(entry)
            if entry.filename.endswith(".jar"):
                result.extend(scan_jar(payload, prefix + entry.filename + "!", budget))
            else:
                result.extend(findings(prefix + entry.filename, payload))
    return result


def metrics(root):
    counts = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    reports = sorted(root.glob("target/*-reports/TEST-*.xml"))
    if not reports:
        raise ValueError("test reports missing")
    for report in reports:
        suite = ET.parse(report).getroot()
        for name in counts:
            counts[name] += int(suite.attrib.get(name, "0"))
    if not counts["tests"] or any(counts[name] for name in ("failures", "errors", "skipped")):
        raise ValueError("tests failed, missing or skipped")
    report = ET.parse(root / "target/site/jacoco/jacoco.xml").getroot()
    counter = report.find("./counter[@type='LINE']")
    if counter is None:
        raise ValueError("LINE coverage missing")
    covered = int(counter.attrib["covered"])
    missed = int(counter.attrib["missed"])
    if covered + missed == 0 or covered / (covered + missed) < 0.80:
        raise ValueError("LINE coverage below 80%")
    return {"tests": counts, "line_covered": covered, "line_missed": missed}


def write_test_summary(root):
    counts = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    reports = sorted(root.glob("target/*-reports/TEST-*.xml"))
    malformed = 0
    for report in reports:
        try:
            suite = ET.parse(report).getroot()
            for name in counts:
                counts[name] += int(suite.attrib.get(name, "0"))
        except (ET.ParseError, OSError, ValueError):
            malformed += 1
    summary = {"state": "diagnostic_only", "reports_found": len(reports),
               "malformed_reports": malformed, "tests": counts}
    output = root / "target/test-summary.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def git(root, *arguments):
    return subprocess.check_output(
        ["git", "-c", "safe.directory=" + root.as_posix(), "-C", str(root), *arguments],
        stderr=subprocess.DEVNULL,
    ).decode().strip()


def verify(root, image=None):
    revision = git(root, "rev-parse", "HEAD")
    if not re.fullmatch("[0-9a-f]{40}", revision):
        raise ValueError("full Git revision required")
    origin = git(root, "remote", "get-url", "origin").removesuffix(".git")
    expected = json.loads((root / "scripts/build-contract.json").read_text())
    if origin != expected["repository"]:
        raise ValueError("repository origin mismatch")
    jars = list((root / "target").glob(expected["jar"]))
    if len(jars) != 1:
        raise ValueError("exactly one executable JAR required")
    jar_bytes = jars[0].read_bytes()
    with zipfile.ZipFile(io.BytesIO(jar_bytes)) as archive:
        for required in expected["required_classes"]:
            bytecode = archive.read(required)
            if bytecode[:4] != b"\xca\xfe\xba\xbe" or int.from_bytes(bytecode[6:8], "big") != 65:
                raise ValueError("Java 21 runtime entrypoint required")
        if any(re.search(r"(^|/)(testcontainers|junit|harness)(/|[-.])", member, re.I) for member in archive.namelist()):
            raise ValueError("test harness in productive package")
    package_findings = scan_jar(jar_bytes)
    source_files = {}
    for entry in ("src", "scripts", ".github", ".mvn", "mvnw", "mvnw.cmd", "pom.xml", "Dockerfile", ".dockerignore"):
        candidate = root / entry
        for path in ([candidate] if candidate.is_file() else candidate.rglob("*")):
            if path.is_symlink():
                raise ValueError("source symlink rejected")
            if path.is_file() and "__pycache__" not in path.parts:
                source_files[path.relative_to(root).as_posix()] = sha256(path.read_bytes())
    for path in (root / "src/main").rglob("*"):
        if path.is_file():
            package_findings.extend(findings(path.relative_to(root).as_posix(), path.read_bytes()))
    evidence = {
        "format_version": 1,
        "state": "local_review_only",
        "repository": origin,
        "base_revision": revision,
        "working_tree_source_sha256": sha256(json.dumps(source_files, sort_keys=True).encode()),
        "dirty": bool(git(root, "status", "--porcelain", "--untracked-files=all")),
        "tracked_diff_sha256": sha256(subprocess.check_output(
            ["git", "-c", "safe.directory=" + root.as_posix(), "-C", str(root), "diff", "HEAD", "--binary"])),
        "metrics": metrics(root),
        "jar": {"file": jars[0].name, "bytes": len(jar_bytes), "sha256": sha256(jar_bytes)},
        "scanner_findings": package_findings,
        "remote": None,
        "image": None,
    }
    if image:
        metadata = json.loads(subprocess.check_output(["docker", "image", "inspect", image]))[0]
        config = metadata["Config"]
        labels = config.get("Labels") or {}
        if labels.get("org.opencontainers.image.source") != origin:
            raise ValueError("image source repository mismatch")
        image_revision = labels.get("org.opencontainers.image.revision")
        if image_revision and (image_revision != revision or evidence["dirty"]):
            raise ValueError("image commit does not identify this clean source")
        if not evidence["dirty"] and image_revision != revision:
            raise ValueError("clean image requires exact Git revision label")
        if metadata["Os"] != "linux" or metadata["Architecture"] != "amd64":
            raise ValueError("linux/amd64 required")
        if config.get("User", "").split(":")[0] in {"", "0", "root"}:
            raise ValueError("non-root image required")
        if config["Entrypoint"] != expected["entrypoint"]:
            raise ValueError("runtime entrypoint mismatch")
        evidence["image"] = {"id": metadata["Id"], "platform": "linux/amd64", "user": config["User"]}
        identifier = subprocess.check_output(["docker", "create", "--network", "none", image]).decode().strip()
        try:
            with tempfile.TemporaryDirectory(prefix="oficina-image-audit-") as folder:
                destination = Path(folder) / "app.jar"
                subprocess.run(["docker", "cp", identifier + ":/app/app.jar", str(destination)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                image_jar = destination.read_bytes()
                evidence["image"]["jar_sha256"] = sha256(image_jar)
                image_findings = scan_jar(image_jar)
                package_findings.extend({"member": "image!" + item["member"], "sha256": item["sha256"]}
                                        for item in image_findings)
        finally:
            subprocess.run(["docker", "rm", "-v", identifier], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    output = root / "target/build-evidence.json"
    output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output), "scanner_findings": len(package_findings)}))
    return not package_findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--image")
    parser.add_argument("--test-summary", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.test_summary:
            write_test_summary(arguments.root.resolve())
            return 0
        return 0 if verify(arguments.root.resolve(), arguments.image) else 1
    except (ValueError, KeyError, OSError, ET.ParseError, zipfile.BadZipFile, subprocess.SubprocessError):
        print("Build verification blocked; inspect local reports (no sensitive payload logged).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
