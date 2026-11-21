import os
import zipfile
import tempfile
import shutil
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Form
from ..config import settings
from ..models.schemas import ScanResult, Vulnerability
from ..models.database import db
from ..services.fingerprinting import ProjectFingerprinter
from ..services.ast_analyzer import PythonASTAnalyzer
from ..services.scanners.semgrep_runner import SemgrepScanner
from ..services.scanners.secret_scanner import SecretScanner
from ..services.scanners.dependency_scanner import DependencyScanner
from ..services.normalizer import FindingNormalizer
from ..services.hallucination_guard import AIHallucinationGuard
from ..services.attack_path_builder import AttackPathBuilder
from ..services.security_dna_builder import SecurityDNABuilder
from ..services.scoring import ScoringEngine
from ..services.regression_radar import RegressionRadar
from ..services.fix_engine import FixEngine
from ..demo_data.bundled_scans import get_demo_scan_result, DEMO_SCAN_ID

router = APIRouter(prefix="/api/scans", tags=["Scans"])

@router.post("/demo", response_model=ScanResult)
def run_demo_scan():
    """Instant demo scan endpoint for live evaluation and demo mode."""
    res = get_demo_scan_result()
    db.save_project(res.project_id, res.project_name)
    db.save_scan(res.scan_id, res.project_id, res.project_name, res.score_breakdown.score, res.model_dump())
    return res

@router.post("/upload", response_model=ScanResult)
async def upload_and_scan(
    file: UploadFile = File(...),
    project_name: Optional[str] = Form("Uploaded Project")
):
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only .zip project archives are supported.")

    # Guard against upload size bomb
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    content = await file.read()
    if len(content) > max_bytes:
        raise HTTPException(status_code=400, detail=f"Uploaded file exceeds {settings.max_upload_size_mb}MB limit.")

    temp_dir = tempfile.mkdtemp(prefix="vulnex_upload_")
    zip_path = os.path.join(temp_dir, "project.zip")
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        with open(zip_path, "wb") as f:
            f.write(content)

        # Secure ZIP extraction with Zip Slip defense
        with zipfile.ZipFile(zip_path, 'r') as z:
            for member in z.namelist():
                # Check for zip slip traversal
                dest_path = os.path.abspath(os.path.join(extract_dir, member))
                if not dest_path.startswith(os.path.abspath(extract_dir)):
                    raise HTTPException(status_code=400, detail="Malicious path traversal detected in ZIP archive.")
            z.extractall(extract_dir)

        # 1. Project Fingerprinting
        fingerprinter = ProjectFingerprinter(extract_dir)
        fingerprint = fingerprinter.analyze()

        # 2. Python AST Analysis
        ast_analyzer = PythonASTAnalyzer(extract_dir)
        ast_findings = []
        for f in fingerprint["files"]:
            if f.endswith('.py'):
                ast_findings.extend(ast_analyzer.analyze_file(f))

        # 3. Semgrep Static Analysis
        semgrep_scanner = SemgrepScanner(extract_dir)
        sem_findings = semgrep_scanner.scan()

        # 4. Secret Scanner (Gitleaks + Entropy)
        secret_scanner = SecretScanner(extract_dir)
        sec_findings = secret_scanner.scan()

        # 5. Dependency Scanner (OSV)
        dep_scanner = DependencyScanner(extract_dir)
        dep_findings = dep_scanner.scan()

        raw_all = ast_findings + sem_findings + sec_findings + dep_findings

        # 6. Normalization & Evidence Chains
        normalizer = FindingNormalizer(extract_dir)
        normalized = normalizer.normalize(raw_all)

        # 7. Hallucination Guard & Attack Paths & Fix Proposals
        guard = AIHallucinationGuard()
        path_builder = AttackPathBuilder()
        fix_engine = FixEngine()

        for v in normalized:
            v["scan_id"] = ""
            # Hallucination Guard check
            hg_result = guard.evaluate(v, v.get("code_snippet", ""))
            v["hallucination_status"] = hg_result["hallucination_status"]
            v["confidence"] = hg_result["adjusted_confidence"]
            
            # Attack Path
            v["attack_path"] = path_builder.build_for_finding(v).model_dump()

            # Pre-generate Fix Proposal
            v["fix"] = fix_engine.generate_fix(v).model_dump()

        # 8. Security DNA
        dna_builder = SecurityDNABuilder()
        security_dna = dna_builder.build(fingerprint, normalized)

        # 9. Regression Radar vs Previous Scan
        project_id = f"proj_{uuid.uuid4().hex[:8]}"
        prev_scans = db.get_project_scans(project_id)
        prev_vulns = prev_scans[-1].get("vulnerabilities", []) if prev_scans else []
        regression_radar = RegressionRadar()
        regressions = regression_radar.compare_scans(prev_vulns, normalized)

        # 10. Scoring & Radar & Passport
        scoring_engine = ScoringEngine()
        score_breakdown = scoring_engine.calculate_score(normalized, regressions)
        radar_metrics = scoring_engine.calculate_radar(normalized)
        passport = scoring_engine.build_passport(project_id, project_name or "Scanned App", score_breakdown.score, normalized)

        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        for v in normalized:
            v["scan_id"] = scan_id

        result = ScanResult(
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name or "Scanned App",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            status="COMPLETED",
            vulnerabilities=[Vulnerability(**v) for v in normalized],
            security_dna=security_dna,
            radar=radar_metrics,
            score_breakdown=score_breakdown,
            passport=passport,
            regressions_detected=regressions
        )

        # Save to database
        db.save_project(project_id, project_name or "Scanned App")
        db.save_scan(scan_id, project_id, project_name or "Scanned App", score_breakdown.score, result.model_dump())

        return result

    finally:
        # Secure cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)

@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str):
    if scan_id == DEMO_SCAN_ID:
        return get_demo_scan_result()

    data = db.get_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return data

@router.get("/{scan_id}/vulnerabilities", response_model=List[Vulnerability])
def get_scan_vulnerabilities(scan_id: str):
    if scan_id == DEMO_SCAN_ID:
        return get_demo_scan_result().vulnerabilities

    data = db.get_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return data.get("vulnerabilities", [])
