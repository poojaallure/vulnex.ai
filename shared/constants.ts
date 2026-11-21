/**
 * VULNEX AI - Shared Constants
 */

export const SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export const EXPLOITABILITY_LEVELS = ["LOW", "MEDIUM", "HIGH"] as const;

export const FINDING_STATUSES = [
  "DETECTED",
  "SUSPECTED",
  "CONFIRMED",
  "EXPLOITABLE",
  "FIX GENERATED",
  "FIX VERIFIED",
  "FIX FAILED",
  "RESOLVED",
] as const;

export const HALLUCINATION_STATUSES = [
  "VERIFIED",
  "AI SUSPECTED",
  "FALSE POSITIVE CANDIDATE",
] as const;

export const DEFAULT_PORTS = {
  FRONTEND: 3000,
  BACKEND: 8000,
  DEMO_PROJECT: 8001,
} as const;

export const API_ROUTES = {
  HEALTH: "/api/health",
  UPLOAD_SCAN: "/api/scans/upload",
  DEMO_SCAN: "/api/scans/demo",
  GET_SCAN: (scanId: string) => `/api/scans/${scanId}`,
  SIMULATE_FIX: "/api/scans/simulate-fix",
  APPLY_FIX: "/api/scans/apply-fix",
  SCAN_HISTORY: (scanId: string) => `/api/scans/${scanId}/history`,
  RESEARCH_METRICS: "/api/research/metrics",
  COPILOT: "/api/copilot",
} as const;
