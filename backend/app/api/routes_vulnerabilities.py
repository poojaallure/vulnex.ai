from fastapi import APIRouter, HTTPException
from typing import Dict, Any, Optional
from ..models.schemas import Vulnerability, FixProposal
from ..models.database import db
from ..services.gemini_analyzer import GeminiAnalyzer
from ..services.fix_engine import FixEngine
from ..demo_data.bundled_scans import get_demo_vulnerabilities

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])

@router.get("/{vuln_id}")
def get_vulnerability(vuln_id: str):
    demo_vulns = {v.id: v for v in get_demo_vulnerabilities()}
    if vuln_id in demo_vulns:
        return demo_vulns[vuln_id]

    conn = db.get_connection()
    c = conn.cursor()
    c.execute('SELECT data_json FROM vulnerabilities WHERE id = ?', (vuln_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")
    import json
    return json.loads(row[0])

@router.post("/{vuln_id}/analyze")
def analyze_with_ai(vuln_id: str):
    vuln_data = get_vulnerability(vuln_id)
    if isinstance(vuln_data, Vulnerability):
        vuln_data = vuln_data.model_dump()

    gemini_analyzer = GeminiAnalyzer()
    analysis = gemini_analyzer.analyze_finding(vuln_data, vuln_data.get("code_snippet", ""))
    return analysis

@router.post("/{vuln_id}/generate-fix", response_model=FixProposal)
def generate_fix(vuln_id: str):
    vuln_data = get_vulnerability(vuln_id)
    if isinstance(vuln_data, Vulnerability):
        vuln_data = vuln_data.model_dump()

    fix_engine = FixEngine()
    fix = fix_engine.generate_fix(vuln_data)
    return fix
