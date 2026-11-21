from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class EvidenceStep(BaseModel):
    step: int
    file: str
    line: int
    code: str
    description: str
    role: str  # SOURCE, PROPAGATION, SINK, SANITIZER

class AttackPathNode(BaseModel):
    id: str
    label: str
    type: str  # INPUT, TRUST_BOUNDARY, VULNERABLE_COMPONENT, SENSITIVE_RESOURCE, EXTERNAL_SERVICE, DATABASE
    description: str

class AttackPathEdge(BaseModel):
    source: str
    target: str
    label: Optional[str] = None
    animated: bool = True

class AttackPath(BaseModel):
    id: str
    title: str
    severity: str
    description: str
    nodes: List[AttackPathNode]
    edges: List[AttackPathEdge]
    narrative: str

class SecurityDNANode(BaseModel):
    id: str
    name: str
    category: str  # APP, AUTH, API, DATABASE, SECRET, EXTERNAL_API, DEPENDENCY, CONFIG
    technology: str
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    files: List[str]
    vulnerabilities_count: int = 0
    attack_surface_desc: str

class SecurityDNAEdge(BaseModel):
    source: str
    target: str
    relation: str

class SecurityDNA(BaseModel):
    nodes: List[SecurityDNANode]
    edges: List[SecurityDNAEdge]
    frameworks: List[str]
    languages: List[str]
    databases: List[str]
    auth_methods: List[str]

class FixProposal(BaseModel):
    id: str
    vulnerability_id: str
    original_code: str
    proposed_fix: str
    why_this_fix: str
    what_changed: str
    security_impact: str
    possible_side_effects: List[str]
    confidence: int  # 0 - 100
    status: str = "GENERATED"  # GENERATED, SIMULATED, VERIFIED, FAILED, APPLIED

class FixSimulationResult(BaseModel):
    fix_id: str
    vulnerability_id: str
    before_critical: int
    before_high: int
    before_medium: int
    after_critical: int
    after_high: int
    after_medium: int
    resolved: bool
    regressions: List[str] = []
    message: str
    verification_status: str  # FIX VERIFIED, FIX FAILED

class Vulnerability(BaseModel):
    id: str
    scan_id: str
    title: str
    cwe: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: int  # 0 - 100
    exploitability: str  # LOW, MEDIUM, HIGH
    status: str  # DETECTED, SUSPECTED, EXPLOITABLE, FIX GENERATED, FIX VERIFIED, FIX FAILED
    hallucination_status: str  # VERIFIED, AI SUSPECTED, FALSE POSITIVE CANDIDATE
    category: str  # Injection, Auth, Secrets, Dependencies, Deserialization, Config
    file: str
    line_start: int
    line_end: int
    code_snippet: str
    evidence_chain: List[EvidenceStep]
    attack_path: Optional[AttackPath] = None
    ai_explanation_beginner: str
    ai_explanation_technical: str
    fix: Optional[FixProposal] = None
    source_scanner: str  # Semgrep, AST, Gitleaks, OSV-Scanner, Gemini

class SecurityScoreBreakdown(BaseModel):
    score: int  # 0 - 100
    base_score: int = 100
    critical_penalty: int
    high_penalty: int
    medium_penalty: int
    low_penalty: int
    secret_penalty: int
    dependency_penalty: int
    delta: int = 0
    audit_trail: List[str]

class SecurityRadarMetrics(BaseModel):
    authentication: int
    authorization: int
    secrets: int
    dependencies: int
    input_validation: int
    api_security: int
    configuration: int
    data_protection: int
    code_safety: int
    ai_confidence: int

class SecurityPassport(BaseModel):
    project_id: str
    project_name: str
    security_score: int
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    verified_fixes_count: int
    open_critical_count: int
    open_high_count: int
    dependency_health_pct: int
    secret_health_pct: int
    attack_surface_rating: str
    ai_confidence_pct: int
    verification_pct: int
    last_verified: str

class TimelineEvent(BaseModel):
    version: str
    scan_id: str
    timestamp: str
    score: int
    score_delta: int
    new_vulnerabilities_count: int
    fixed_vulnerabilities_count: int
    regressions: List[str] = []
    summary: str

class ResearchMetric(BaseModel):
    system_name: str
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    fix_success_rate: float
    verification_success_rate: float
    avg_analysis_time_sec: float
    total_samples: int

class ScanResult(BaseModel):
    scan_id: str
    project_id: str
    project_name: str
    timestamp: str
    status: str
    vulnerabilities: List[Vulnerability]
    security_dna: SecurityDNA
    radar: SecurityRadarMetrics
    score_breakdown: SecurityScoreBreakdown
    passport: SecurityPassport
    regressions_detected: List[str] = []

class Project(BaseModel):
    id: str
    name: str
    created_at: str
    last_scan_id: Optional[str] = None
    scan_count: int = 0

class CopilotQuery(BaseModel):
    project_id: str
    scan_id: Optional[str] = None
    question: str
    current_vulnerability_id: Optional[str] = None
    mode: str = "technical"  # beginner or technical

class CopilotResponse(BaseModel):
    answer: str
    referenced_files: List[str] = []
    recommended_actions: List[str] = []
    confidence: int = 95
