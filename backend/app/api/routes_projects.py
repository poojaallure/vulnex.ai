from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from ..models.schemas import Project, TimelineEvent, SecurityPassport
from ..models.database import db
from ..demo_data.bundled_scans import (
    DEMO_PROJECT_ID, DEMO_PROJECT_NAME, get_demo_timeline, get_demo_scan_result
)

router = APIRouter(prefix="/api/projects", tags=["Projects"])

@router.get("", response_model=List[Project])
def list_projects():
    projects = db.list_projects()
    # Always ensure Demo project is listed
    if not any(p["id"] == DEMO_PROJECT_ID for p in projects):
        projects.insert(0, {
            "id": DEMO_PROJECT_ID,
            "name": DEMO_PROJECT_NAME,
            "created_at": "2026-11-18T14:20:00",
            "last_scan_id": "scan_demo_v1",
            "scan_count": 4
        })
    return projects

@router.get("/{project_id}/timeline", response_model=List[TimelineEvent])
def get_project_timeline(project_id: str):
    if project_id == DEMO_PROJECT_ID:
        return get_demo_timeline()

    scans = db.get_project_scans(project_id)
    if not scans:
        raise HTTPException(status_code=404, detail="No scans found for project.")

    events = []
    prev_score = None
    for idx, s in enumerate(scans):
        curr_score = s.get("score_breakdown", {}).get("score", 50)
        delta = (curr_score - prev_score) if prev_score is not None else 0
        prev_score = curr_score
        events.append(TimelineEvent(
            version=f"v1.{idx}.0",
            scan_id=s.get("scan_id", ""),
            timestamp=s.get("timestamp", ""),
            score=curr_score,
            score_delta=delta,
            new_vulnerabilities_count=len(s.get("vulnerabilities", [])),
            fixed_vulnerabilities_count=sum(1 for v in s.get("vulnerabilities", []) if v.get("status") in ("RESOLVED", "FIX VERIFIED")),
            regressions=s.get("regressions_detected", []),
            summary=f"Scan cycle {idx + 1} completed with score {curr_score}/100."
        ))
    return events

@router.get("/{project_id}/security-passport", response_model=SecurityPassport)
def get_security_passport(project_id: str):
    if project_id == DEMO_PROJECT_ID:
        return get_demo_scan_result().passport

    scans = db.get_project_scans(project_id)
    if not scans:
        raise HTTPException(status_code=404, detail="Project scan data not found.")
    last_scan = scans[-1]
    return last_scan.get("passport")
