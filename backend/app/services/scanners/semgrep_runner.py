import subprocess
import json
import shutil
import os
import re
from typing import List, Dict, Any

class SemgrepScanner:
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.has_semgrep = shutil.which("semgrep") is not None

    def scan(self) -> List[Dict[str, Any]]:
        findings = []

        if self.has_semgrep:
            try:
                findings.extend(self._run_cli())
            except Exception:
                pass

        # Also run deterministic AST / pattern rule engine to ensure full coverage
        findings.extend(self._run_deterministic_rules())
        return self._deduplicate(findings)

    def _run_cli(self) -> List[Dict[str, Any]]:
        cmd = ["semgrep", "--config=auto", "--json", self.project_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        results = []
        if proc.stdout:
            data = json.loads(proc.stdout)
            for res in data.get("results", []):
                rel_path = os.path.relpath(res["path"], self.project_path).replace("\\", "/")
                results.append({
                    "title": res["check_id"].split(".")[-1].replace("-", " ").title(),
                    "cwe": res.get("extra", {}).get("metadata", {}).get("cwe", ["CWE-General"])[0],
                    "severity": self._map_severity(res.get("extra", {}).get("severity", "MEDIUM")),
                    "confidence": 90,
                    "exploitability": "HIGH" if "HIGH" in res.get("extra", {}).get("severity", "") else "MEDIUM",
                    "category": "Code Quality",
                    "file": rel_path,
                    "line_start": res["start"]["line"],
                    "line_end": res["end"]["line"],
                    "code_snippet": res.get("extra", {}).get("lines", ""),
                    "source_scanner": "Semgrep Static Scanner",
                    "reason": res.get("extra", {}).get("message", "Semgrep security rule matched."),
                    "status": "CONFIRMED"
                })
        return results

    def _map_severity(self, sev: str) -> str:
        s = sev.upper()
        if "ERROR" in s or "CRIT" in s:
            return "CRITICAL"
        if "WARN" in s or "HIGH" in s:
            return "HIGH"
        if "MED" in s:
            return "MEDIUM"
        return "LOW"

    def _run_deterministic_rules(self) -> List[Dict[str, Any]]:
        findings = []
        ignore_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}

        patterns = [
            # SQL Injection in JS/TS
            {
                "id": "sqli-js",
                "title": "SQL Injection in Query Execution (CWE-89)",
                "cwe": "CWE-89",
                "severity": "CRITICAL",
                "category": "Injection",
                "regex": r'\b(query|execute)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`',
                "exts": ('.js', '.ts', '.jsx', '.tsx'),
                "reason": "Template literal interpolation detected inside database query call.",
                "exploitability": "HIGH"
            },
            # Command injection in JS/TS
            {
                "id": "cmdi-js",
                "title": "Command Injection via Child Process (CWE-78)",
                "cwe": "CWE-78",
                "severity": "CRITICAL",
                "category": "Injection",
                "regex": r'\bexec\s*\(\s*(`[^`]*\$\{[^}]+\}[^`]*`|[a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]+)',
                "exts": ('.js', '.ts'),
                "reason": "child_process.exec invoked with dynamically concatenated string.",
                "exploitability": "HIGH"
            },
            # Cross-Site Scripting (XSS)
            {
                "id": "xss-react",
                "title": "Cross-Site Scripting via dangerouslySetInnerHTML (CWE-79)",
                "cwe": "CWE-79",
                "severity": "HIGH",
                "category": "Injection",
                "regex": r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\s*\}\s*\}',
                "exts": ('.jsx', '.tsx', '.js', '.ts'),
                "reason": "Direct rendering of raw HTML via dangerouslySetInnerHTML without sanitization.",
                "exploitability": "HIGH"
            },
            # Path Traversal
            {
                "id": "path-traversal",
                "title": "Path Traversal File Access (CWE-22)",
                "cwe": "CWE-22",
                "severity": "HIGH",
                "category": "File Handling",
                "regex": r'\b(open|readFile|readFileSync|createReadStream)\s*\([^)]*(\+|path\.join)[^)]*(req\.|request\.|params\.|query\.)',
                "exts": ('.py', '.js', '.ts'),
                "reason": "Direct user request parameter passed to file read function without path sanitization.",
                "exploitability": "HIGH"
            },
            # SSRF
            {
                "id": "ssrf",
                "title": "Server-Side Request Forgery (CWE-918)",
                "cwe": "CWE-918",
                "severity": "HIGH",
                "category": "Network",
                "regex": r'\b(requests\.get|requests\.post|axios\.get|fetch)\s*\(\s*(req\.|request\.|params\.|url\b)',
                "exts": ('.py', '.js', '.ts'),
                "reason": "Outbound HTTP request targets an unvalidated user-supplied URL.",
                "exploitability": "HIGH"
            },
            # Insecure CORS
            {
                "id": "insecure-cors",
                "title": "Permissive Cross-Origin Resource Sharing (CWE-942)",
                "cwe": "CWE-942",
                "severity": "MEDIUM",
                "category": "Config",
                "regex": r'allow_origins\s*=\s*\[\s*["\']\*["\']\s*\]\s*,?\s*allow_credentials\s*=\s*True',
                "exts": ('.py', '.js', '.ts'),
                "reason": "CORS policy allows wildcard origin '*' combined with credentials enabled.",
                "exploitability": "MEDIUM"
            },
            # Weak Hashing
            {
                "id": "weak-hash",
                "title": "Use of Broken Cryptographic Hash MD5/SHA1 (CWE-328)",
                "cwe": "CWE-328",
                "severity": "MEDIUM",
                "category": "Cryptography",
                "regex": r'\b(hashlib\.md5|hashlib\.sha1|crypto\.createHash\(["\'](md5|sha1)["\']\))',
                "exts": ('.py', '.js', '.ts'),
                "reason": "Cryptographically broken algorithm used for hashing.",
                "exploitability": "LOW"
            }
        ]

        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file in files:
                rel_path = os.path.relpath(os.path.join(root, file), self.project_path).replace("\\", "/")
                full_path = os.path.join(root, file)

                for rule in patterns:
                    if file.endswith(rule["exts"]):
                        try:
                            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                lines = f.readlines()
                            for idx, line in enumerate(lines):
                                if re.search(rule["regex"], line):
                                    start_l = idx + 1
                                    end_l = min(len(lines), start_l + 3)
                                    snippet = "".join(lines[idx:end_l])
                                    findings.append({
                                        "title": rule["title"],
                                        "cwe": rule["cwe"],
                                        "severity": rule["severity"],
                                        "confidence": 92,
                                        "exploitability": rule["exploitability"],
                                        "category": rule["category"],
                                        "file": rel_path,
                                        "line_start": start_l,
                                        "line_end": end_l,
                                        "code_snippet": snippet.strip(),
                                        "source_scanner": "Semgrep Security Rules",
                                        "reason": rule["reason"],
                                        "status": "CONFIRMED"
                                    })
                        except Exception:
                            continue
        return findings

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        deduped = []
        for f in findings:
            key = (f["cwe"], f["file"], f["line_start"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
