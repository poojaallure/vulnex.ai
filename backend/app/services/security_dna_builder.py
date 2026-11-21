from typing import Dict, Any, List
from ..models.schemas import SecurityDNA, SecurityDNANode, SecurityDNAEdge

class SecurityDNABuilder:
    def build(self, fingerprint: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> SecurityDNA:
        nodes = []
        edges = []

        # Categorize vulnerabilities
        vuln_by_cat: Dict[str, List[Dict[str, Any]]] = {}
        for v in vulnerabilities:
            cat = v.get("category", "General")
            vuln_by_cat.setdefault(cat, []).append(v)

        # 1. Central Core: APP
        framework_str = ", ".join(fingerprint.get("frameworks", ["Python Core"])) or "Python Core"
        app_vulns = len(vuln_by_cat.get("Injection", [])) + len(vuln_by_cat.get("General", []))
        nodes.append(SecurityDNANode(
            id="node_dna_app",
            name="Application Core",
            category="APP",
            technology=framework_str,
            risk_level="CRITICAL" if app_vulns > 0 else "LOW",
            files=[f for f in fingerprint.get("files", []) if any(f.endswith(e) for e in ('.py', '.js', '.ts'))][:5],
            vulnerabilities_count=app_vulns,
            attack_surface_desc="Core application controllers and business logic processing ingress requests."
        ))

        # 2. AUTH Boundary
        auth_str = ", ".join(fingerprint.get("auth", ["Session Auth"])) or "None Configured"
        auth_vulns = len(vuln_by_cat.get("Auth", []))
        nodes.append(SecurityDNANode(
            id="node_dna_auth",
            name="Authentication & Session",
            category="AUTH",
            technology=auth_str,
            risk_level="HIGH" if auth_vulns > 0 else "LOW",
            files=[f for f in fingerprint.get("files", []) if "auth" in f.lower() or "login" in f.lower()][:3],
            vulnerabilities_count=auth_vulns,
            attack_surface_desc="Token generation, password verification, and identity perimeter."
        ))
        edges.append(SecurityDNAEdge(source="node_dna_app", target="node_dna_auth", relation="authenticates"))

        # 3. API Ingress
        api_str = ", ".join(fingerprint.get("apis", ["REST Endpoints"])) or "REST Endpoints"
        nodes.append(SecurityDNANode(
            id="node_dna_api",
            name="API Ingress Perimeter",
            category="API",
            technology=api_str,
            risk_level="HIGH" if app_vulns > 0 else "MEDIUM",
            files=[f for f in fingerprint.get("files", []) if "api" in f.lower() or "route" in f.lower()][:4],
            vulnerabilities_count=app_vulns,
            attack_surface_desc="Public network entrypoints accepting external query parameters and JSON payloads."
        ))
        edges.append(SecurityDNAEdge(source="node_dna_api", target="node_dna_app", relation="routes_to"))

        # 4. DATABASE Sink
        db_str = ", ".join(fingerprint.get("databases", ["SQLite/Relational"])) or "SQLite"
        sqli_vulns = len([v for v in vulnerabilities if "89" in v.get("cwe", "")])
        nodes.append(SecurityDNANode(
            id="node_dna_db",
            name="Database & Data Storage",
            category="DATABASE",
            technology=db_str,
            risk_level="CRITICAL" if sqli_vulns > 0 else "LOW",
            files=[f for f in fingerprint.get("files", []) if "db" in f.lower() or "data" in f.lower() or "model" in f.lower()][:3],
            vulnerabilities_count=sqli_vulns,
            attack_surface_desc="Data storage backend storing persistent tables, user credentials, and tenant records."
        ))
        edges.append(SecurityDNAEdge(source="node_dna_app", target="node_dna_db", relation="queries"))

        # 5. SECRET Vault / Credentials
        secret_vulns = len(vuln_by_cat.get("Secrets", []))
        nodes.append(SecurityDNANode(
            id="node_dna_secret",
            name="Secrets & Keys",
            category="SECRET",
            technology="Environment / In-memory Keys",
            risk_level="CRITICAL" if secret_vulns > 0 else "LOW",
            files=fingerprint.get("sensitive_files", [])[:4],
            vulnerabilities_count=secret_vulns,
            attack_surface_desc="Private cryptographic keys, API access tokens, and signing secrets."
        ))
        edges.append(SecurityDNAEdge(source="node_dna_app", target="node_dna_secret", relation="reads_keys"))

        # 6. EXTERNAL SERVICES
        ext_str = ", ".join(fingerprint.get("external_services", ["Third-Party APIs"])) or "External APIs"
        nodes.append(SecurityDNANode(
            id="node_dna_ext",
            name="External Service Integrations",
            category="EXTERNAL_API",
            technology=ext_str,
            risk_level="MEDIUM",
            files=[f for f in fingerprint.get("files", []) if "client" in f.lower() or "service" in f.lower()][:3],
            vulnerabilities_count=0,
            attack_surface_desc="Outbound HTTP/gRPC network calls to third-party vendor platforms."
        ))
        edges.append(SecurityDNAEdge(source="node_dna_secret", target="node_dna_ext", relation="authenticates_with"))
        edges.append(SecurityDNAEdge(source="node_dna_app", target="node_dna_ext", relation="invokes"))

        # 7. DEPENDENCIES
        dep_vulns = len(vuln_by_cat.get("Dependencies", []))
        nodes.append(SecurityDNANode(
            id="node_dna_dep",
            name="Third-Party Dependencies",
            category="DEPENDENCY",
            technology="OSS Supply Chain",
            risk_level="HIGH" if dep_vulns > 0 else "LOW",
            files=[f for f in fingerprint.get("files", []) if f in ("requirements.txt", "package.json", "Pipfile")],
            vulnerabilities_count=dep_vulns,
            attack_surface_desc="Upstream open-source software libraries linked into the execution runtime."
        ))
        edges.append(SecurityDNAEdge(source="node_dna_app", target="node_dna_dep", relation="imports"))

        return SecurityDNA(
            nodes=nodes,
            edges=edges,
            frameworks=fingerprint.get("frameworks", []),
            languages=fingerprint.get("languages", []),
            databases=fingerprint.get("databases", []),
            auth_methods=fingerprint.get("auth", [])
        )
