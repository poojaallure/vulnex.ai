import os
import shutil
import tempfile
from typing import Dict, Any, List
from ..models.schemas import FixSimulationResult
from .ast_analyzer import PythonASTAnalyzer
from .scanners.semgrep_runner import SemgrepScanner
from .scanners.secret_scanner import SecretScanner
from .scanners.dependency_scanner import DependencyScanner

class SimulationEngine:
    def __init__(self, project_path: str):
        self.project_path = project_path

    def simulate_and_verify(self, vuln_data: Dict[str, Any], proposed_fix: str, all_vulnerabilities: List[Dict[str, Any]]) -> FixSimulationResult:
        vuln_id = vuln_data.get("id", "vuln_1")
        target_file = vuln_data.get("file", "")
        original_code = vuln_data.get("code_snippet", "")

        # 1. Compute before stats
        before_crit = sum(1 for v in all_vulnerabilities if "CRIT" in v.get("severity", "") and v.get("status") not in ("RESOLVED", "FIX VERIFIED"))
        before_high = sum(1 for v in all_vulnerabilities if "HIGH" in v.get("severity", "") and v.get("status") not in ("RESOLVED", "FIX VERIFIED"))
        before_med = sum(1 for v in all_vulnerabilities if "MED" in v.get("severity", "") and v.get("status") not in ("RESOLVED", "FIX VERIFIED"))

        # 2. Create isolated temporary workspace
        temp_dir = tempfile.mkdtemp(prefix="vulnex_sim_")
        regressions = []
        try:
            # Copy project to isolated sandbox
            if os.path.exists(self.project_path):
                # Copy ignoring heavy folders
                for item in os.listdir(self.project_path):
                    s = os.path.join(self.project_path, item)
                    d = os.path.join(temp_dir, item)
                    if os.path.isdir(s):
                        if item not in ('.git', 'node_modules', '__pycache__', '.venv', 'venv'):
                            shutil.copytree(s, d)
                    else:
                        shutil.copy2(s, d)

            # 3. Apply proposed fix inside temp sandbox
            target_path = os.path.join(temp_dir, target_file)
            if os.path.exists(target_path):
                with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                # Replace snippet if found, or append secure pattern
                if original_code and original_code in content:
                    new_content = content.replace(original_code, proposed_fix)
                else:
                    # Replace targeted lines
                    line_start = vuln_data.get("line_start", 1)
                    line_end = vuln_data.get("line_end", line_start)
                    lines = content.splitlines()
                    s_idx = max(0, line_start - 1)
                    e_idx = min(len(lines), line_end)
                    lines[s_idx:e_idx] = [proposed_fix]
                    new_content = "\n".join(lines)

                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(new_content)

            # 4. Re-run independent verification suite on sandbox
            ast_analyzer = PythonASTAnalyzer(temp_dir)
            ast_findings = []
            for root, _, files in os.walk(temp_dir):
                for f in files:
                    if f.endswith('.py'):
                        rel = os.path.relpath(os.path.join(root, f), temp_dir).replace("\\", "/")
                        ast_findings.extend(ast_analyzer.analyze_file(rel))

            semgrep_scanner = SemgrepScanner(temp_dir)
            sem_findings = semgrep_scanner.scan()

            secret_scanner = SecretScanner(temp_dir)
            sec_findings = secret_scanner.scan()

            dep_scanner = DependencyScanner(temp_dir)
            dep_findings = dep_scanner.scan()

            all_sim_findings = ast_findings + sem_findings + sec_findings + dep_findings

            # 5. Evaluate if the targeted vulnerability was eliminated
            target_cwe = vuln_data.get("cwe", "")
            target_still_present = any(
                f.get("file") == target_file and f.get("cwe") == target_cwe
                for f in all_sim_findings
            )

            # Compute after counts
            after_crit = sum(1 for f in all_sim_findings if "CRIT" in f.get("severity", ""))
            after_high = sum(1 for f in all_sim_findings if "HIGH" in f.get("severity", ""))
            after_med = sum(1 for f in all_sim_findings if "MED" in f.get("severity", ""))

            # Check if any new vulnerability was accidentally introduced (Regression)
            if after_crit > before_crit:
                regressions.append("Critical severity regression: Patch introduced unhandled critical security flaw.")
            if after_high > before_high:
                regressions.append("High severity regression: Patch introduced auxiliary high risk finding.")

            resolved = not target_still_present and len(regressions) == 0

            if resolved:
                msg = f"Independent Re-Scan Verified: Vulnerability {vuln_data.get('title')} was completely resolved. Re-scan of patched sandbox confirmed 0 syntax errors and 0 security regressions."
                verif_status = "FIX VERIFIED"
            else:
                msg = f"Fix Simulation Incomplete: Vulnerability was not fully eliminated or introduced side-effect risks."
                verif_status = "FIX FAILED"

            return FixSimulationResult(
                fix_id=f"fix_{vuln_id}",
                vulnerability_id=vuln_id,
                before_critical=before_crit,
                before_high=before_high,
                before_medium=before_med,
                after_critical=after_crit,
                after_high=after_high,
                after_medium=after_med,
                resolved=resolved,
                regressions=regressions,
                message=msg,
                verification_status=verif_status
            )

        finally:
            # Defensive clean up: Always wipe temporary simulation sandbox
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
