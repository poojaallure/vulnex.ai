/**
 * VULNEX AI - Shared Type Definitions
 * Unified contracts between Frontend, Backend, and Tooling.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type Exploitability = "LOW" | "MEDIUM" | "HIGH";

export type FindingStatus =
  | "DETECTED"
  | "SUSPECTED"
  | "CONFIRMED"
  | "EXPLOITABLE"
  | "FIX GENERATED"
  | "FIX VERIFIED"
  | "FIX FAILED"
  | "RESOLVED";

export type HallucinationStatus =
  | "VERIFIED"
  | "AI SUSPECTED"
  | "FALSE POSITIVE CANDIDATE";

export interface EvidenceStep {
  step: number;
  file: string;
  line: number;
  code: string;
  description: string;
  role: "SOURCE" | "PROPAGATION" | "SINK" | "SANITIZER";
}

export interface AttackPathNode {
  id: string;
  label: string;
  type:
    | "INPUT"
    | "TRUST_BOUNDARY"
    | "VULNERABLE_COMPONENT"
    | "SENSITIVE_RESOURCE"
    | "EXTERNAL_SERVICE"
    | "DATABASE";
  description: string;
}

export interface AttackPathEdge {
  source: string;
  target: string;
  label?: string;
  animated?: boolean;
}

export interface AttackPath {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  narrative: string;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
}

export interface FixProposal {
  id: string;
  vulnerability_id: string;
  original_code: string;
  fixed_code: string;
  diff: string;
  why_this_fix: string;
  what_changed: string;
  security_impact: string;
  side_effects: string;
  confidence: number;
  applied: boolean;
  verified: boolean;
}

export interface FixSimulationResult {
  before_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  after_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  eliminated_vulnerabilities: string[];
  remaining_vulnerabilities: string[];
  new_issues_introduced: string[];
  regression_detected: boolean;
  summary: string;
}

export interface SecurityScoreBreakdown {
  score: number;
  grade: string;
  critical_penalty: number;
  high_penalty: number;
  medium_penalty: number;
  verified_bonus: number;
  audit_trail: string[];
}

export interface SecurityPassport {
  project_name: string;
  project_id: string;
  scan_id: string;
  score: number;
  grade: string;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  timestamp: string;
  critical_count: number;
  verified_fixes_count: number;
  dependency_health: string;
  secret_health: string;
  attack_surface_nodes: number;
  verification_rate_pct: number;
  hallucination_guarded_pct: number;
}
