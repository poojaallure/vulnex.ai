from typing import Dict, Any, List
from ..models.schemas import AttackPath, AttackPathNode, AttackPathEdge

class AttackPathBuilder:
    def build_for_finding(self, finding: Dict[str, Any]) -> AttackPath:
        cwe = finding.get("cwe", "")
        title = finding.get("title", "")
        file = finding.get("file", "app.py")

        if "89" in cwe: # SQL Injection
            nodes = [
                AttackPathNode(
                    id="node_user",
                    label="Untrusted User",
                    type="INPUT",
                    description="External web client crafts malicious input with SQL syntax payloads."
                ),
                AttackPathNode(
                    id="node_api",
                    label="Public API Route",
                    type="TRUST_BOUNDARY",
                    description=f"HTTP endpoint in {file} accepts query parameters without boundary schema filtering."
                ),
                AttackPathNode(
                    id="node_query",
                    label="SQL Construction",
                    type="VULNERABLE_COMPONENT",
                    description="Application dynamically interpolates unescaped user parameter directly into SQL string."
                ),
                AttackPathNode(
                    id="node_db",
                    label="Relational Database",
                    type="DATABASE",
                    description="Database engine executes modified SQL syntax with attacker's arbitrary conditions."
                ),
                AttackPathNode(
                    id="node_data",
                    label="Sensitive User Records",
                    type="SENSITIVE_RESOURCE",
                    description="Database dumps private authentication hashes and personal data across boundary."
                )
            ]
            edges = [
                AttackPathEdge(source="node_user", target="node_api", label="HTTP GET /search?q=' OR 1=1--", animated=True),
                AttackPathEdge(source="node_api", target="node_query", label="Unsanitized Parameter", animated=True),
                AttackPathEdge(source="node_query", target="node_db", label="Malformed Raw Query", animated=True),
                AttackPathEdge(source="node_db", target="node_data", label="Unauthorized Exfiltration", animated=True)
            ]
            narrative = "An attacker sends a crafted SQL payload through the query parameter. The application lacks parameterization, causing the database to execute arbitrary SQL commands and return unauthorized sensitive table records."

        elif "78" in cwe: # Command Injection
            nodes = [
                AttackPathNode(
                    id="node_user",
                    label="Attacker Client",
                    type="INPUT",
                    description="Attacker sends shell metacharacters (e.g. ; rm -rf / or ; curl c2.net) in request payload."
                ),
                AttackPathNode(
                    id="node_api",
                    label="Network Entrypoint",
                    type="TRUST_BOUNDARY",
                    description=f"Controller handler in {file} passes string directly to process executor."
                ),
                AttackPathNode(
                    id="node_shell",
                    label="System Shell (shell=True)",
                    type="VULNERABLE_COMPONENT",
                    description="Host OS shell interprets semicolon or pipe character as command delimiter."
                ),
                AttackPathNode(
                    id="node_host",
                    label="Host Environment",
                    type="SENSITIVE_RESOURCE",
                    description="Secondary commands execute with host process privileges, allowing full system compromise."
                )
            ]
            edges = [
                AttackPathEdge(source="node_user", target="node_api", label="Crafted Metacharacters", animated=True),
                AttackPathEdge(source="node_api", target="node_shell", label="String Concatenation", animated=True),
                AttackPathEdge(source="node_shell", target="node_host", label="Arbitrary OS Execution", animated=True)
            ]
            narrative = "The attacker supplies shell metacharacters into the API input. Because shell=True is enabled, the operating system executes the attacker's payload as a secondary command, leading to potential remote code execution."

        elif "798" in cwe: # Hardcoded Secrets
            nodes = [
                AttackPathNode(
                    id="node_src",
                    label="Source Repository",
                    type="INPUT",
                    description=f"Plaintext credential committed into {file}."
                ),
                AttackPathNode(
                    id="node_extract",
                    label="Public/Insider Access",
                    type="TRUST_BOUNDARY",
                    description="Attacker or third-party inspects commit history or compiled bundle."
                ),
                AttackPathNode(
                    id="node_service",
                    label="Protected Cloud Resource",
                    type="EXTERNAL_SERVICE",
                    description="Attacker uses discovered credential directly against live production cloud APIs."
                ),
                AttackPathNode(
                    id="node_res",
                    label="Production Infrastructure",
                    type="SENSITIVE_RESOURCE",
                    description="Bypasses normal web authentication and accesses storage buckets and databases directly."
                )
            ]
            edges = [
                AttackPathEdge(source="node_src", target="node_extract", label="Credential Scrape", animated=True),
                AttackPathEdge(source="node_extract", target="node_service", label="Direct API Auth", animated=True),
                AttackPathEdge(source="node_service", target="node_res", label="Total Perimeter Bypass", animated=True)
            ]
            narrative = "The hardcoded secret can be extracted from source code or container artifacts. The attacker uses this key to authenticate directly to production APIs, completely bypassing perimeter authentication controls."

        elif "306" in cwe: # Broken Auth
            nodes = [
                AttackPathNode(
                    id="node_anon",
                    label="Unauthenticated Visitor",
                    type="INPUT",
                    description="Anonymous internet user discovers administrative endpoint URL."
                ),
                AttackPathNode(
                    id="node_route",
                    label="Admin Endpoint",
                    type="TRUST_BOUNDARY",
                    description=f"Privileged route in {file} lacks authorization guard or session verification."
                ),
                AttackPathNode(
                    id="node_logic",
                    label="Privileged Business Logic",
                    type="VULNERABLE_COMPONENT",
                    description="Executes destructive state mutations or exports internal administrative records."
                ),
                AttackPathNode(
                    id="node_db",
                    label="System Database",
                    type="DATABASE",
                    description="Tenant data or system records are deleted or altered without permission."
                )
            ]
            edges = [
                AttackPathEdge(source="node_anon", target="node_route", label="Direct HTTP Request", animated=True),
                AttackPathEdge(source="node_route", target="node_logic", label="Missing Auth Gate", animated=True),
                AttackPathEdge(source="node_logic", target="node_db", label="Unauthorized Mutation", animated=True)
            ]
            narrative = "An anonymous client makes a direct request to a privileged endpoint. Because the endpoint does not enforce authentication or role verification, the privileged action executes with full access."

        else: # Generic
            nodes = [
                AttackPathNode(
                    id="node_client",
                    label="Client Input",
                    type="INPUT",
                    description="Attacker submits input exceeding expected parameters."
                ),
                AttackPathNode(
                    id="node_app",
                    label="Application Logic",
                    type="VULNERABLE_COMPONENT",
                    description=f"Component in {file} processes input insecurely."
                ),
                AttackPathNode(
                    id="node_target",
                    label="Downstream Resource",
                    type="SENSITIVE_RESOURCE",
                    description="Security boundary compromised."
                )
            ]
            edges = [
                AttackPathEdge(source="node_client", target="node_app", label="Untrusted Payload", animated=True),
                AttackPathEdge(source="node_app", target="node_target", label="Defect Exploitation", animated=True)
            ]
            narrative = f"A vulnerability in {file} allows an attacker to manipulate application state and compromise downstream resources."

        return AttackPath(
            id=f"path_{finding.get('id', '1')}",
            title=f"Attack Vector: {title}",
            severity=finding.get("severity", "HIGH"),
            description=finding.get("reason", "Defensive attack sequence model."),
            nodes=nodes,
            edges=edges,
            narrative=narrative
        )
