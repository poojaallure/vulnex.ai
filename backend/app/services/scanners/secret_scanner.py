import os
import re
import math
import shutil
import subprocess
import json
from typing import List, Dict, Any

class SecretScanner:
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.has_gitleaks = shutil.which("gitleaks") is not None

    def scan(self) -> List[Dict[str, Any]]:
        findings = []
        if self.has_gitleaks:
            try:
                findings.extend(self._run_gitleaks_cli())
            except Exception:
                pass

        findings.extend(self._run_entropy_and_rules())
        return self._deduplicate(findings)

    def _mask_secret(self, val: str) -> str:
        val = val.strip()
        if len(val) <= 6:
            return "***"
        return f"{val[:3]}...{val[-3:]}"

    def _calc_shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    def _run_gitleaks_cli(self) -> List[Dict[str, Any]]:
        report_file = os.path.join(self.project_path, ".gitleaks_tmp.json")
        cmd = ["gitleaks", "detect", "--source", self.project_path, "--no-git", "--report-path", report_file, "--report-format", "json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        results = []
        if os.path.exists(report_file):
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        rel = os.path.relpath(item.get("File", ""), self.project_path).replace("\\", "/")
                        masked = self._mask_secret(item.get("Secret", ""))
                        results.append({
                            "title": f"Exposed Secret: {item.get('Description', 'Hardcoded Credential')} (CWE-798)",
                            "cwe": "CWE-798",
                            "severity": "CRITICAL",
                            "confidence": 98,
                            "exploitability": "HIGH",
                            "category": "Secrets",
                            "file": rel,
                            "line_start": item.get("StartLine", 1),
                            "line_end": item.get("EndLine", 1),
                            "code_snippet": f"Secret Token detected: {masked}",
                            "source_scanner": "Gitleaks CLI",
                            "reason": f"Credential exposed directly in repository: {item.get('Description')}",
                            "status": "CONFIRMED"
                        })
            finally:
                if os.path.exists(report_file):
                    os.remove(report_file)
        return results

    def _run_entropy_and_rules(self) -> List[Dict[str, Any]]:
        patterns = [
            {
                "name": "AWS Access Key",
                "regex": r'(A3T[A-Z0-9]|AKIA[0-9A-Z]{16})',
                "severity": "CRITICAL",
                "confidence": 99
            },
            {
                "name": "GitHub Personal Access Token",
                "regex": r'(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,})',
                "severity": "CRITICAL",
                "confidence": 99
            },
            {
                "name": "Stripe Live Secret Key",
                "regex": r'(sk_live_[0-9a-zA-Z]{24,})',
                "severity": "CRITICAL",
                "confidence": 98
            },
            {
                "name": "Private Cryptographic Key",
                "regex": r'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
                "severity": "CRITICAL",
                "confidence": 100
            },
            {
                "name": "Database Connection String with Credentials",
                "regex": r'(postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_]+:[^@\s\'"]+@[a-zA-Z0-9\.\-_]+',
                "severity": "HIGH",
                "confidence": 96
            },
            {
                "name": "Hardcoded API Key / JWT Secret",
                "regex": r'(?:jwt_secret|api_key|secret_key|auth_token)\s*=\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']',
                "severity": "HIGH",
                "confidence": 92
            }
        ]

        findings = []
        ignore_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}

        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file in files:
                rel_path = os.path.relpath(os.path.join(root, file), self.project_path).replace("\\", "/")
                full_path = os.path.join(root, file)

                # Skip binaries / very large files
                try:
                    if os.path.getsize(full_path) > 500000:
                        continue
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for line_idx, line in enumerate(lines):
                    for pat in patterns:
                        match = re.search(pat["regex"], line, re.IGNORECASE)
                        if match:
                            secret_token = match.group(0)
                            masked = self._mask_secret(secret_token)
                            findings.append({
                                "title": f"Hardcoded Secret: {pat['name']} (CWE-798)",
                                "cwe": "CWE-798",
                                "severity": pat["severity"],
                                "confidence": pat["confidence"],
                                "exploitability": "HIGH",
                                "category": "Secrets",
                                "file": rel_path,
                                "line_start": line_idx + 1,
                                "line_end": line_idx + 1,
                                "code_snippet": line.replace(secret_token, masked).strip(),
                                "source_scanner": "Gitleaks / Secret Engine",
                                "reason": f"High-confidence secret token detected: {pat['name']}.",
                                "status": "CONFIRMED"
                            })
        return findings

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        deduped = []
        for f in findings:
            key = (f["file"], f["line_start"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
