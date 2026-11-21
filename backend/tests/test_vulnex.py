import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.ast_analyzer import PythonASTAnalyzer
from backend.app.services.scanners.secret_scanner import SecretScanner
from backend.app.services.scanners.dependency_scanner import DependencyScanner
from backend.app.services.scoring import ScoringEngine

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "VULNEX" in data["app"]

def test_demo_scan():
    response = client.post("/api/scans/demo")
    assert response.status_code == 200
    data = response.json()
    assert data["project_name"] == "AI-Commerce Engine"
    assert len(data["vulnerabilities"]) > 0
    assert data["score_breakdown"]["score"] > 0
    assert data["passport"]["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

def test_research_metrics():
    response = client.get("/api/research/metrics")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    # Check VULNEX Hybrid F1 score is higher than Traditional & AI-Only
    hybrid = next(m for m in data if "VULNEX" in m["system_name"])
    assert hybrid["f1_score"] >= 0.90
    assert hybrid["verification_success_rate"] >= 0.90

def test_copilot():
    response = client.post("/api/copilot", json={
        "project_id": "proj_aicommerce_01",
        "question": "Which vulnerability should I fix first?",
        "mode": "technical"
    })
    assert response.status_code == 200
    data = response.json()
    assert len(data["answer"]) > 10
    assert len(data["recommended_actions"]) > 0

def test_scoring_engine():
    engine = ScoringEngine()
    test_vulns = [
        {"severity": "CRITICAL", "confidence": 95, "status": "CONFIRMED", "category": "Injection"},
        {"severity": "HIGH", "confidence": 90, "status": "CONFIRMED", "category": "Auth"}
    ]
    breakdown = engine.calculate_score(test_vulns)
    assert breakdown.score < 100
    assert breakdown.critical_penalty > 0
    assert len(breakdown.audit_trail) > 0

def test_real_zip_upload_and_scan():
    with open("demo-project.zip", "rb") as f:
        response = client.post(
            "/api/scans/upload",
            files={"file": ("demo-project.zip", f, "application/zip")},
            data={"project_name": "Demo Uploaded Project"}
        )
    assert response.status_code == 200
    data = response.json()
    assert data["project_name"] == "Demo Uploaded Project"
    # Ensure real scanner identified the SQL Injection and Secret in demo-project
    cwes = [v["cwe"] for v in data["vulnerabilities"]]
    assert "CWE-89" in cwes # SQL Injection
    assert "CWE-798" in cwes # Secret
    assert data["score_breakdown"]["score"] < 100
    assert len(data["security_dna"]["nodes"]) >= 4
