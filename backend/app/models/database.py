import sqlite3
import json
import os
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from ..config import settings

DB_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "vulnex.db")

class Database:
    def __init__(self):
        self._init_sqlite()
        self.supabase_url = settings.supabase_url.rstrip("/")
        self.supabase_key = settings.supabase_service_role_key or settings.supabase_anon_key

    @property
    def has_supabase(self) -> bool:
        return bool(self.supabase_url and self.supabase_key)

    def _supabase_headers(self) -> Dict[str, str]:
        return {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates"
        }

    def _init_sqlite(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Projects table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_scan_id TEXT,
            scan_count INTEGER DEFAULT 0
        )
        ''')

        # Scans table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            project_name TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL,
            score INTEGER NOT NULL,
            data_json TEXT NOT NULL,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
        ''')

        # Vulnerabilities table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            title TEXT NOT NULL,
            cwe TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            status TEXT NOT NULL,
            file TEXT NOT NULL,
            data_json TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        ''')

        # Fixes table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS fixes (
            id TEXT PRIMARY KEY,
            vulnerability_id TEXT NOT NULL,
            proposed_fix TEXT NOT NULL,
            status TEXT NOT NULL,
            data_json TEXT NOT NULL,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
        )
        ''')

        # Research benchmarks table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS research_runs (
            id TEXT PRIMARY KEY,
            system_name TEXT NOT NULL,
            data_json TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        ''')

        conn.commit()
        conn.close()

    def get_connection(self):
        conn = sqlite3.connect(DB_FILE, timeout=30.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def save_project(self, project_id: str, name: str):
        conn = self.get_connection()
        c = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        c.execute('''
        INSERT OR REPLACE INTO projects (id, name, created_at, scan_count)
        VALUES (?, ?, COALESCE((SELECT created_at FROM projects WHERE id = ?), ?), 
               COALESCE((SELECT scan_count FROM projects WHERE id = ?), 0))
        ''', (project_id, name, project_id, now, project_id))
        conn.commit()
        conn.close()

        # Sync to Supabase if configured
        if self.has_supabase:
            try:
                requests.post(
                    f"{self.supabase_url}/rest/v1/projects",
                    headers=self._supabase_headers(),
                    json={"id": project_id, "name": name, "created_at": now},
                    timeout=5
                )
            except Exception as e:
                print(f"[Supabase Sync] Project save warning: {e}")

    def list_projects(self) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('SELECT id, name, created_at, last_scan_id, scan_count FROM projects ORDER BY created_at DESC')
        rows = c.fetchall()
        conn.close()
        return [
            {
                "id": r[0],
                "name": r[1],
                "created_at": r[2],
                "last_scan_id": r[3],
                "scan_count": r[4]
            }
            for r in rows
        ]

    def save_scan(self, scan_id: str, project_id: str, project_name: str, score: int, data: Dict[str, Any]):
        conn = self.get_connection()
        c = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        c.execute('''
        INSERT OR REPLACE INTO scans (id, project_id, project_name, timestamp, status, score, data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, project_id, project_name, now, "COMPLETED", score, json.dumps(data)))

        c.execute('''
        UPDATE projects
        SET last_scan_id = ?, scan_count = scan_count + 1
        WHERE id = ?
        ''', (scan_id, project_id))

        # Save individual vulnerabilities
        for v in data.get("vulnerabilities", []):
            c.execute('''
            INSERT OR REPLACE INTO vulnerabilities (id, scan_id, title, cwe, severity, confidence, status, file, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (v["id"], scan_id, v["title"], v["cwe"], v["severity"], v["confidence"], v["status"], v["file"], json.dumps(v)))

        conn.commit()
        conn.close()

        # Sync to Supabase if configured
        if self.has_supabase:
            try:
                requests.post(
                    f"{self.supabase_url}/rest/v1/scans",
                    headers=self._supabase_headers(),
                    json={
                        "id": scan_id,
                        "project_id": project_id,
                        "project_name": project_name,
                        "timestamp": now,
                        "status": "COMPLETED",
                        "score": score,
                        "data_json": data
                    },
                    timeout=5
                )
            except Exception as e:
                print(f"[Supabase Sync] Scan save warning: {e}")

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        # Check Supabase first if configured
        if self.has_supabase:
            try:
                resp = requests.get(
                    f"{self.supabase_url}/rest/v1/scans?id=eq.{scan_id}&select=data_json",
                    headers=self._supabase_headers(),
                    timeout=5
                )
                if resp.status_code == 200:
                    items = resp.json()
                    if items:
                        return items[0]["data_json"]
            except Exception as e:
                print(f"[Supabase Sync] Scan fetch warning: {e}")

        conn = self.get_connection()
        c = conn.cursor()
        c.execute('SELECT data_json FROM scans WHERE id = ?', (scan_id,))
        row = c.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
        return None

    def get_project_scans(self, project_id: str) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('SELECT data_json FROM scans WHERE project_id = ? ORDER BY timestamp ASC', (project_id,))
        rows = c.fetchall()
        conn.close()
        return [json.loads(r[0]) for r in rows]

    def update_vulnerability(self, vuln_id: str, updated_vuln_data: Dict[str, Any]):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
        UPDATE vulnerabilities 
        SET status = ?, data_json = ?
        WHERE id = ?
        ''', (updated_vuln_data["status"], json.dumps(updated_vuln_data), vuln_id))

        # Also update inside the scan JSON if present
        scan_id = updated_vuln_data.get("scan_id")
        if scan_id:
            c.execute('SELECT data_json FROM scans WHERE id = ?', (scan_id,))
            row = c.fetchone()
            if row:
                scan_data = json.loads(row[0])
                for idx, v in enumerate(scan_data.get("vulnerabilities", [])):
                    if v["id"] == vuln_id:
                        scan_data["vulnerabilities"][idx] = updated_vuln_data
                        break
                c.execute('UPDATE scans SET data_json = ? WHERE id = ?', (json.dumps(scan_data), scan_id))

        conn.commit()
        conn.close()

db = Database()
