from typing import List, Dict, Any

class RegressionRadar:
    def compare_scans(self, previous_vulns: List[Dict[str, Any]], current_vulns: List[Dict[str, Any]]) -> List[str]:
        regressions = []
        
        # Build lookup for previous findings
        # Key: (cwe, file)
        prev_map = {(v.get("cwe"), v.get("file")): v for v in previous_vulns}
        curr_map = {(v.get("cwe"), v.get("file")): v for v in current_vulns}

        for (cwe, file), prev_v in prev_map.items():
            # If it was marked RESOLVED or FIX VERIFIED previously, but now reappears
            if prev_v.get("status") in ("RESOLVED", "FIX VERIFIED"):
                curr_v = curr_map.get((cwe, file))
                if curr_v and curr_v.get("status") not in ("RESOLVED", "FIX VERIFIED"):
                    line = curr_v.get("line_start", 1)
                    title = curr_v.get("title", "Security Vulnerability")
                    regressions.append(
                        f"REGRESSION DETECTED: {title} ({cwe}) was previously resolved, but has returned in '{file}:{line}'!"
                    )

        # Check for newly introduced secrets
        prev_secrets = [v for v in previous_vulns if v.get("category") == "Secrets"]
        curr_secrets = [v for v in current_vulns if v.get("category") == "Secrets" and v.get("status") not in ("RESOLVED", "FIX VERIFIED")]
        if len(curr_secrets) > len(prev_secrets):
            diff = len(curr_secrets) - len(prev_secrets)
            regressions.append(f"NEW SECRET RISK: {diff} new unencrypted credential(s) committed since last verified scan.")

        # Check for newly introduced vulnerable dependencies
        prev_deps = [v for v in previous_vulns if v.get("category") == "Dependencies"]
        curr_deps = [v for v in current_vulns if v.get("category") == "Dependencies" and v.get("status") not in ("RESOLVED", "FIX VERIFIED")]
        if len(curr_deps) > len(prev_deps):
            diff = len(curr_deps) - len(prev_deps)
            regressions.append(f"SUPPLY CHAIN REGRESSION: {diff} newly vulnerable package version(s) introduced.")

        return regressions
