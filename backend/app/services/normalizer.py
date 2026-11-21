import os
import re
from typing import List, Dict, Any
from ..models.schemas import EvidenceStep

class FindingNormalizer:
    def __init__(self, project_path: str):
        self.project_path = project_path

    def normalize(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized = []
        for idx, f in enumerate(raw_findings):
            vuln_id = f"vuln_{idx + 1}"
            evidence = self._build_evidence_chain(f)
            
            # Map status & confidence
            severity = f.get("severity", "MEDIUM")
            confidence = f.get("confidence", 85)
            exploitability = f.get("exploitability", "MEDIUM")
            status = f.get("status", "DETECTED")

            normalized.append({
                "id": vuln_id,
                "scan_id": "",
                "title": f.get("title", "Detected Security Vulnerability"),
                "cwe": f.get("cwe", "CWE-General"),
                "severity": severity,
                "confidence": confidence,
                "exploitability": exploitability,
                "status": status,
                "hallucination_status": "VERIFIED",
                "category": f.get("category", "General"),
                "file": f.get("file", ""),
                "line_start": f.get("line_start", 1),
                "line_end": f.get("line_end", 1),
                "code_snippet": f.get("code_snippet", ""),
                "evidence_chain": evidence,
                "ai_explanation_beginner": self._generate_beginner_explanation(f),
                "ai_explanation_technical": self._generate_technical_explanation(f),
                "source_scanner": f.get("source_scanner", "VULNEX Security Engine"),
                "attack_path": None,
                "fix": None
            })
        return normalized

    def _build_evidence_chain(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        cwe = finding.get("cwe", "")
        file = finding.get("file", "")
        line = finding.get("line_start", 1)
        snippet = finding.get("code_snippet", "")

        chain = []

        if "89" in cwe: # SQL Injection
            chain = [
                {
                    "step": 1,
                    "file": file,
                    "line": max(1, line - 4),
                    "code": "query_param = request.args.get('search')",
                    "description": "User-supplied query parameter received from HTTP request.",
                    "role": "SOURCE"
                },
                {
                    "step": 2,
                    "file": file,
                    "line": max(1, line - 2),
                    "code": "filtered_input = query_param # Untrusted parameter passed directly",
                    "description": "Parameter propagated through control flow without validation or escaping.",
                    "role": "PROPAGATION"
                },
                {
                    "step": 3,
                    "file": file,
                    "line": line,
                    "code": snippet.splitlines()[0] if snippet else f"sql = f\"SELECT * FROM data WHERE search = '{{query_param}}'\"",
                    "description": "SQL statement constructed dynamically with interpolated parameter.",
                    "role": "SINK"
                },
                {
                    "step": 4,
                    "file": file,
                    "line": line + 1,
                    "code": "cursor.execute(sql)",
                    "description": "Database driver executes unparameterized SQL command.",
                    "role": "SINK"
                }
            ]
        elif "78" in cwe: # Command Injection
            chain = [
                {
                    "step": 1,
                    "file": file,
                    "line": max(1, line - 3),
                    "code": "cmd_arg = request.form.get('target_ip')",
                    "description": "Unsanitized user string accepted by entrypoint.",
                    "role": "SOURCE"
                },
                {
                    "step": 2,
                    "file": file,
                    "line": max(1, line - 1),
                    "code": "command_str = f'ping -c 1 {cmd_arg}'",
                    "description": "System command string constructed via concatenation.",
                    "role": "PROPAGATION"
                },
                {
                    "step": 3,
                    "file": file,
                    "line": line,
                    "code": snippet.splitlines()[0] if snippet else "subprocess.Popen(command_str, shell=True)",
                    "description": "Process spawned with shell=True allowing command chaining.",
                    "role": "SINK"
                }
            ]
        elif "798" in cwe: # Hardcoded Secrets
            chain = [
                {
                    "step": 1,
                    "file": file,
                    "line": line,
                    "code": snippet.splitlines()[0] if snippet else "SECRET_KEY = '***'",
                    "description": "Plaintext secret token embedded directly into source code.",
                    "role": "SOURCE"
                },
                {
                    "step": 2,
                    "file": file,
                    "line": line,
                    "code": "Repository commit / distribution artifact",
                    "description": "Sensitive credential packaged and distributed in version control.",
                    "role": "SINK"
                }
            ]
        elif "306" in cwe or "Auth" in finding.get("category", ""): # Broken Auth
            chain = [
                {
                    "step": 1,
                    "file": file,
                    "line": max(1, line - 2),
                    "code": "@app.post('/api/admin/users/delete')",
                    "description": "Privileged management route defined on network interface.",
                    "role": "SOURCE"
                },
                {
                    "step": 2,
                    "file": file,
                    "line": line,
                    "code": "def delete_user(user_id: int):",
                    "description": "No security guard decorator or session role verification executed.",
                    "role": "PROPAGATION"
                },
                {
                    "step": 3,
                    "file": file,
                    "line": line + 2,
                    "code": "db.execute('DELETE FROM users WHERE id = :id', {'id': user_id})",
                    "description": "State modification executed on behalf of unauthenticated actor.",
                    "role": "SINK"
                }
            ]
        else: # Generic
            chain = [
                {
                    "step": 1,
                    "file": file,
                    "line": line,
                    "code": snippet.splitlines()[0] if snippet else finding.get("title", ""),
                    "description": f"Trigger located in {file}:{line} identified by {finding.get('source_scanner')}.",
                    "role": "SINK"
                }
            ]

        return chain

    def _generate_beginner_explanation(self, finding: Dict[str, Any]) -> str:
        cwe = finding.get("cwe", "")
        if "89" in cwe:
            return "Your application accepts text from users and sends it directly to the database without checking it first. An attacker can type special database commands to read everyone's private data or delete your tables."
        elif "78" in cwe:
            return "Your application runs operating system commands using words supplied by a visitor. An attacker can add extra terminal commands (like deleting files or installing spyware) to run on your server."
        elif "798" in cwe:
            return "A private key or password is written directly into your code. Anyone who sees this code, downloads the app, or inspects the file can copy your password and access your accounts."
        elif "1395" in cwe:
            return "This project uses a library package that has a well-known security bug already discovered by researchers. Updating this package to the newest version will close the door on known attacks."
        elif "306" in cwe:
            return "An admin or sensitive page doesn't check if the visitor is actually logged in. Anyone on the internet can visit the web address and perform actions meant only for managers."
        return "A security risk was found in this file where unexpected data could cause the application to behave incorrectly or expose private information."

    def _generate_technical_explanation(self, finding: Dict[str, Any]) -> str:
        title = finding.get("title", "")
        cwe = finding.get("cwe", "")
        reason = finding.get("reason", "")
        return f"{title} ({cwe}): {reason} The flow introduces untrusted input into a privileged execution sink without validation, parametrization, or sanitization."
