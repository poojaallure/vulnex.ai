from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone
from ..models.schemas import SecurityScoreBreakdown, SecurityRadarMetrics, SecurityPassport

class ScoringEngine:
    def calculate_score(self, vulnerabilities: List[Dict[str, Any]], regressions: List[str] = []) -> SecurityScoreBreakdown:
        score = 100
        critical_penalty = 0
        high_penalty = 0
        medium_penalty = 0
        low_penalty = 0
        secret_penalty = 0
        dependency_penalty = 0
        audit_trail = []

        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        sec_count = 0
        dep_count = 0

        for v in vulnerabilities:
            # Only count unresolved vulnerabilities
            if v.get("status") in ("RESOLVED", "FIX VERIFIED"):
                continue

            sev = v.get("severity", "MEDIUM").upper()
            cat = v.get("category", "")
            conf = v.get("confidence", 80) / 100.0

            if "CRIT" in sev:
                crit_count += 1
                pen = int(22 * conf)
                critical_penalty += pen
            elif "HIGH" in sev:
                high_count += 1
                pen = int(14 * conf)
                high_penalty += pen
            elif "MED" in sev:
                med_count += 1
                pen = int(7 * conf)
                medium_penalty += pen
            else:
                low_count += 1
                pen = int(3 * conf)
                low_penalty += pen

            if cat == "Secrets":
                sec_count += 1
                secret_penalty += 8
            elif cat == "Dependencies":
                dep_count += 1
                dependency_penalty += 5

        # Regressions penalty
        regression_penalty = len(regressions) * 15

        total_deductions = critical_penalty + high_penalty + medium_penalty + low_penalty + secret_penalty + dependency_penalty + regression_penalty
        final_score = max(0, min(100, 100 - total_deductions))

        if crit_count > 0:
            audit_trail.append(f"-{critical_penalty} pts: {crit_count} Critical Vulnerabilit{'ies' if crit_count > 1 else 'y'}")
        if high_count > 0:
            audit_trail.append(f"-{high_penalty} pts: {high_count} High Vulnerabilit{'ies' if high_count > 1 else 'y'}")
        if med_count > 0:
            audit_trail.append(f"-{medium_penalty} pts: {med_count} Medium Vulnerabilit{'ies' if med_count > 1 else 'y'}")
        if low_count > 0:
            audit_trail.append(f"-{low_penalty} pts: {low_count} Low Vulnerabilit{'ies' if low_count > 1 else 'y'}")
        if sec_count > 0:
            audit_trail.append(f"-{secret_penalty} pts: {sec_count} Exposed Credential{'s' if sec_count > 1 else ''}")
        if dep_count > 0:
            audit_trail.append(f"-{dependency_penalty} pts: {dep_count} Vulnerable Dependenc{'ies' if dep_count > 1 else 'y'}")
        if regressions:
            audit_trail.append(f"-{regression_penalty} pts: {len(regressions)} Security Regression(s) Detected!")

        if not audit_trail:
            audit_trail.append("Full 100 pts: Zero active vulnerabilities detected across static, AST, secret, and dependency checks.")

        return SecurityScoreBreakdown(
            score=final_score,
            base_score=100,
            critical_penalty=critical_penalty,
            high_penalty=high_penalty,
            medium_penalty=medium_penalty,
            low_penalty=low_penalty,
            secret_penalty=secret_penalty,
            dependency_penalty=dependency_penalty,
            audit_trail=audit_trail
        )

    def calculate_radar(self, vulnerabilities: List[Dict[str, Any]]) -> SecurityRadarMetrics:
        # Default high scores
        scores = {
            "auth": 95,
            "secrets": 98,
            "deps": 94,
            "input": 92,
            "api": 90,
            "config": 96,
            "data": 94,
            "safety": 92,
            "confidence": 95
        }

        for v in vulnerabilities:
            if v.get("status") in ("RESOLVED", "FIX VERIFIED"):
                continue
            cat = v.get("category", "")
            cwe = v.get("cwe", "")
            sev = v.get("severity", "MEDIUM")
            weight = 25 if "CRIT" in sev else (15 if "HIGH" in sev else 8)

            if "Auth" in cat or "306" in cwe:
                scores["auth"] = max(20, scores["auth"] - weight)
            if "Secrets" in cat or "798" in cwe:
                scores["secrets"] = max(15, scores["secrets"] - weight)
            if "Dependencies" in cat:
                scores["deps"] = max(25, scores["deps"] - weight)
            if "Injection" in cat or "89" in cwe or "78" in cwe:
                scores["input"] = max(15, scores["input"] - weight)
                scores["safety"] = max(20, scores["safety"] - weight)
            if "Config" in cat:
                scores["config"] = max(30, scores["config"] - weight)

        return SecurityRadarMetrics(
            authentication=scores["auth"],
            authorization=max(20, scores["auth"] - 10),
            secrets=scores["secrets"],
            dependencies=scores["deps"],
            input_validation=scores["input"],
            api_security=scores["api"],
            configuration=scores["config"],
            data_protection=scores["data"],
            code_safety=scores["safety"],
            ai_confidence=93
        )

    def build_passport(self, project_id: str, project_name: str, score: int, vulnerabilities: List[Dict[str, Any]]) -> SecurityPassport:
        crit = sum(1 for v in vulnerabilities if "CRIT" in v.get("severity", "") and v.get("status") not in ("RESOLVED", "FIX VERIFIED"))
        high = sum(1 for v in vulnerabilities if "HIGH" in v.get("severity", "") and v.get("status") not in ("RESOLVED", "FIX VERIFIED"))
        sec = sum(1 for v in vulnerabilities if v.get("category") == "Secrets" and v.get("status") not in ("RESOLVED", "FIX VERIFIED"))
        dep = sum(1 for v in vulnerabilities if v.get("category") == "Dependencies" and v.get("status") not in ("RESOLVED", "FIX VERIFIED"))
        verified_fixes = sum(1 for v in vulnerabilities if v.get("status") in ("RESOLVED", "FIX VERIFIED"))

        if score >= 85:
            risk = "LOW"
        elif score >= 60:
            risk = "MEDIUM"
        elif score >= 40:
            risk = "HIGH"
        else:
            risk = "CRITICAL"

        total_issues = len(vulnerabilities)
        verif_pct = int((verified_fixes / total_issues * 100)) if total_issues > 0 else 100

        return SecurityPassport(
            project_id=project_id,
            project_name=project_name,
            security_score=score,
            risk_level=risk,
            verified_fixes_count=verified_fixes,
            open_critical_count=crit,
            open_high_count=high,
            dependency_health_pct=max(0, 100 - (dep * 20)),
            secret_health_pct=max(0, 100 - (sec * 50)),
            attack_surface_rating="RESTRICTED" if crit == 0 else "ELEVATED",
            ai_confidence_pct=92,
            verification_pct=verif_pct,
            last_verified=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        )
