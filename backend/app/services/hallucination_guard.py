from typing import Dict, Any, List

class AIHallucinationGuard:
    """
    Evaluates findings against multiple independent deterministic signals
    to prevent AI hallucinations and false positives.
    """
    def evaluate(self, finding: Dict[str, Any], raw_code: str) -> Dict[str, Any]:
        cwe = finding.get("cwe", "")
        source_scanner = finding.get("source_scanner", "")
        evidence_chain = finding.get("evidence_chain", [])
        snippet = finding.get("code_snippet", "")

        # Signal 1: AST / Deterministic Scanner signal
        has_deterministic_signal = any(
            s in source_scanner for s in ("AST", "Semgrep", "Gitleaks", "OSV")
        )

        # Signal 2: Evidence chain depth
        has_evidence_chain = len(evidence_chain) >= 2

        # Check for False Positive signals:
        # e.g., SQLi was flagged, but parameterized placeholder is already used!
        is_false_positive_candidate = False
        fp_reason = ""

        if "89" in cwe:
            if re_has_param_markers(snippet) and not ("JoinedStr" in str(finding) or "f\"" in snippet):
                is_false_positive_candidate = True
                fp_reason = "Query parameters appear to be safely passed as tuple arguments."

        if is_false_positive_candidate:
            return {
                "hallucination_status": "FALSE POSITIVE CANDIDATE",
                "adjusted_confidence": max(10, finding.get("confidence", 80) - 50),
                "guard_reason": f"AI Hallucination Guard detected contradictory evidence: {fp_reason}"
            }

        if has_deterministic_signal and has_evidence_chain:
            return {
                "hallucination_status": "VERIFIED",
                "adjusted_confidence": min(99, max(88, finding.get("confidence", 90))),
                "guard_reason": "Multiple independent signals confirm vulnerability: Static scanner + AST structural flow + multi-stage evidence."
            }

        return {
            "hallucination_status": "AI SUSPECTED",
            "adjusted_confidence": min(65, finding.get("confidence", 70)),
            "guard_reason": "AI suspicion — circumstantial signals without complete deterministic data-flow proof."
        }

def re_has_param_markers(s: str) -> bool:
    import re
    return bool(re.search(r'execute\s*\(\s*["\'][^"\']+["\']\s*,\s*\(', s))
