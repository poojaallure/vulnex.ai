import os
import re
import json
import shutil
import subprocess
from typing import List, Dict, Any

VULNERABLE_PACKAGE_DB = {
    "pyyaml": [
        {"max_v": "5.4.0", "cve": "CVE-2020-14343", "severity": "CRITICAL", "desc": "Arbitrary code execution through untrusted YAML deserialization in PyYAML."}
    ],
    "requests": [
        {"max_v": "2.31.0", "cve": "CVE-2023-32681", "severity": "MEDIUM", "desc": "Proxy-Authorization header leak to unintended destination servers on HTTP redirect."}
    ],
    "urllib3": [
        {"max_v": "2.0.7", "cve": "CVE-2023-45803", "severity": "HIGH", "desc": "Request body leak on 303 redirect in urllib3 HTTP client."}
    ],
    "cryptography": [
        {"max_v": "41.0.0", "cve": "CVE-2023-38325", "severity": "HIGH", "desc": "Null pointer dereference vulnerability in cryptography X.509 certificate processing."}
    ],
    "sqlparse": [
        {"max_v": "0.4.4", "cve": "CVE-2023-30608", "severity": "HIGH", "desc": "Regular Expression Denial of Service (ReDoS) parsing deeply nested SQL queries."}
    ],
    "flask": [
        {"max_v": "2.2.5", "cve": "CVE-2023-30861", "severity": "HIGH", "desc": "Cache-Control misconfiguration leading to sensitive session cookie disclosure."}
    ],
    "lodash": [
        {"max_v": "4.17.21", "cve": "CVE-2020-8203", "severity": "HIGH", "desc": "Prototype pollution via zipObjectDeep function in lodash."}
    ],
    "jsonwebtoken": [
        {"max_v": "9.0.0", "cve": "CVE-2022-23529", "severity": "CRITICAL", "desc": "Remote code execution via insecure key retrieval in jsonwebtoken verify()."}
    ],
    "axios": [
        {"max_v": "1.6.0", "cve": "CVE-2023-45857", "severity": "HIGH", "desc": "Cross-Site Request Forgery and SSRF vector in Axios client."}
    ],
    "express": [
        {"max_v": "4.19.2", "cve": "CVE-2024-29041", "severity": "MEDIUM", "desc": "Open redirect vulnerability via malformed URL encodings in express."}
    ]
}

class DependencyScanner:
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.has_osv = shutil.which("osv-scanner") is not None

    def scan(self) -> List[Dict[str, Any]]:
        findings = []
        if self.has_osv:
            try:
                findings.extend(self._run_osv_cli())
            except Exception:
                pass

        findings.extend(self._scan_manifests())
        return self._deduplicate(findings)

    def _run_osv_cli(self) -> List[Dict[str, Any]]:
        cmd = ["osv-scanner", "--json", "-r", self.project_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        results = []
        if proc.stdout:
            try:
                data = json.loads(proc.stdout)
                for res in data.get("results", []):
                    pkg_src = res.get("source", {}).get("path", "")
                    rel = os.path.relpath(pkg_src, self.project_path).replace("\\", "/") if pkg_src else "dependencies"
                    for pkg in res.get("packages", []):
                        pkg_info = pkg.get("package", {})
                        for vuln in pkg.get("vulnerabilities", []):
                            results.append({
                                "title": f"Vulnerable Dependency: {pkg_info.get('name')} ({vuln.get('id')})",
                                "cwe": "CWE-1395",
                                "severity": "HIGH",
                                "confidence": 95,
                                "exploitability": "MEDIUM",
                                "category": "Dependencies",
                                "file": rel,
                                "line_start": 1,
                                "line_end": 1,
                                "code_snippet": f"{pkg_info.get('name')}=={pkg_info.get('version')}",
                                "source_scanner": "OSV-Scanner CLI",
                                "reason": vuln.get("summary", "Known public vulnerability in package."),
                                "status": "CONFIRMED"
                            })
            except Exception:
                pass
        return results

    def _parse_version(self, v_str: str) -> tuple:
        parts = re.findall(r'\d+', v_str)
        return tuple(int(p) for p in parts[:3])

    def _is_vulnerable(self, current: str, max_v: str) -> bool:
        try:
            curr_parts = self._parse_version(current)
            max_parts = self._parse_version(max_v)
            return curr_parts < max_parts
        except Exception:
            return False

    def _scan_manifests(self) -> List[Dict[str, Any]]:
        findings = []

        # 1. requirements.txt
        req_path = os.path.join(self.project_path, "requirements.txt")
        if os.path.exists(req_path):
            with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    m = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*(?:==|<=|<|>=)?\s*([0-9\.]+)?', line)
                    if m:
                        pkg_name = m.group(1).lower()
                        ver = m.group(2) or "0.0.0"
                        if pkg_name in VULNERABLE_PACKAGE_DB:
                            for adv in VULNERABLE_PACKAGE_DB[pkg_name]:
                                if self._is_vulnerable(ver, adv["max_v"]):
                                    findings.append({
                                        "title": f"Vulnerable Library: {pkg_name} ({adv['cve']})",
                                        "cwe": "CWE-1395",
                                        "severity": adv["severity"],
                                        "confidence": 96,
                                        "exploitability": "MEDIUM",
                                        "category": "Dependencies",
                                        "file": "requirements.txt",
                                        "line_start": line_num,
                                        "line_end": line_num,
                                        "code_snippet": line,
                                        "source_scanner": "OSV-Scanner Advisory DB",
                                        "reason": f"{adv['desc']} Detected version: {ver}, safe upgrade required.",
                                        "status": "CONFIRMED"
                                    })

        # 2. package.json
        pkg_path = os.path.join(self.project_path, "package.json")
        if os.path.exists(pkg_path):
            try:
                with open(pkg_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for pkg_name, ver_str in deps.items():
                    clean_ver = re.sub(r'[\^~>=<]', '', ver_str)
                    clean_name = pkg_name.lower()
                    if clean_name in VULNERABLE_PACKAGE_DB:
                        for adv in VULNERABLE_PACKAGE_DB[clean_name]:
                            if self._is_vulnerable(clean_ver, adv["max_v"]):
                                findings.append({
                                    "title": f"Vulnerable Dependency: {clean_name} ({adv['cve']})",
                                    "cwe": "CWE-1395",
                                    "severity": adv["severity"],
                                    "confidence": 96,
                                    "exploitability": "MEDIUM",
                                    "category": "Dependencies",
                                    "file": "package.json",
                                    "line_start": 1,
                                    "line_end": 1,
                                    "code_snippet": f'"{pkg_name}": "{ver_str}"',
                                    "source_scanner": "OSV-Scanner Advisory DB",
                                    "reason": f"{adv['desc']} Installed version: {clean_ver}.",
                                    "status": "CONFIRMED"
                                })
            except Exception:
                pass

        return findings

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        deduped = []
        for f in findings:
            key = (f["file"], f["title"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
