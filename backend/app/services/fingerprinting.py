import os
import re
from typing import Dict, List, Any, Set

class ProjectFingerprinter:
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.files: List[str] = []
        self._collect_files()

    def _collect_files(self):
        ignore_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', '.next'}
        for root, dirs, filenames in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for f in filenames:
                rel_path = os.path.relpath(os.path.join(root, f), self.project_path).replace("\\", "/")
                self.files.append(rel_path)

    def analyze(self) -> Dict[str, Any]:
        languages = self._detect_languages()
        frameworks = self._detect_frameworks()
        databases = self._detect_databases()
        auth_mechanisms = self._detect_auth()
        apis = self._detect_apis()
        external_services = self._detect_external_services()
        sensitive_files = self._detect_sensitive_files()

        return {
            "languages": list(languages),
            "frameworks": list(frameworks),
            "databases": list(databases),
            "auth": list(auth_mechanisms),
            "apis": list(apis),
            "external_services": list(external_services),
            "sensitive_files": sensitive_files,
            "total_files": len(self.files),
            "files": self.files
        }

    def _detect_languages(self) -> Set[str]:
        langs = set()
        for f in self.files:
            lower = f.lower()
            if lower.endswith(('.py', '.pyw')):
                langs.add("Python")
            elif lower.endswith(('.ts', '.tsx')):
                langs.add("TypeScript")
            elif lower.endswith(('.js', '.jsx', '.mjs')):
                langs.add("JavaScript")
            elif lower.endswith('.go'):
                langs.add("Go")
            elif lower.endswith(('.java', '.kt')):
                langs.add("Java")
            elif lower.endswith('.rs'):
                langs.add("Rust")
            elif lower.endswith(('.sql', '.prisma')):
                langs.add("SQL")
        return langs

    def _detect_frameworks(self) -> Set[str]:
        fws = set()
        req_content = self._read_file_safe("requirements.txt") + self._read_file_safe("Pipfile") + self._read_file_safe("pyproject.toml")
        pkg_content = self._read_file_safe("package.json")

        # Python
        if re.search(r'\bfastapi\b', req_content, re.IGNORECASE):
            fws.add("FastAPI")
        if re.search(r'\bflask\b', req_content, re.IGNORECASE):
            fws.add("Flask")
        if re.search(r'\bdjango\b', req_content, re.IGNORECASE):
            fws.add("Django")

        # JS/TS
        if "next" in pkg_content:
            fws.add("Next.js")
        if "express" in pkg_content:
            fws.add("Express")
        if "react" in pkg_content:
            fws.add("React")
        if "nestjs" in pkg_content:
            fws.add("NestJS")

        # Also search source code signatures
        for f in self.files[:30]:
            if f.endswith('.py'):
                c = self._read_file_safe(f)
                if "FastAPI(" in c or "from fastapi import" in c:
                    fws.add("FastAPI")
                if "Flask(" in c or "from flask import" in c:
                    fws.add("Flask")
            elif f.endswith(('.js', '.ts')):
                c = self._read_file_safe(f)
                if "express()" in c or "require('express')" in c:
                    fws.add("Express")
        return fws

    def _detect_databases(self) -> Set[str]:
        dbs = set()
        all_text = ""
        for f in self.files:
            if f.endswith(('requirements.txt', 'package.json', 'schema.prisma', 'docker-compose.yml', 'settings.py', 'database.py', 'db.py', 'config.py')):
                all_text += " " + self._read_file_safe(f)

        if re.search(r'\b(postgresql|psycopg2|asyncpg|postgres)\b', all_text, re.IGNORECASE):
            dbs.add("PostgreSQL")
        if re.search(r'\b(mysql|mysqlclient|pymysql)\b', all_text, re.IGNORECASE):
            dbs.add("MySQL")
        if re.search(r'\b(sqlite|sqlite3)\b', all_text, re.IGNORECASE):
            dbs.add("SQLite")
        if re.search(r'\b(mongo|mongodb|pymongo|mongoose)\b', all_text, re.IGNORECASE):
            dbs.add("MongoDB")
        if re.search(r'\b(redis|aioredis)\b', all_text, re.IGNORECASE):
            dbs.add("Redis")
        if re.search(r'\bsupabase\b', all_text, re.IGNORECASE):
            dbs.add("Supabase (PostgreSQL)")

        if not dbs:
            for f in self.files:
                if f.endswith('.py'):
                    c = self._read_file_safe(f)
                    if "sqlite3" in c:
                        dbs.add("SQLite")
        return dbs

    def _detect_auth(self) -> Set[str]:
        auth = set()
        for f in self.files:
            c = self._read_file_safe(f)
            if re.search(r'\b(jwt|jsonwebtoken|pyjwt)\b', c, re.IGNORECASE):
                auth.add("JSON Web Tokens (JWT)")
            if re.search(r'\b(oauth|oauth2|passport)\b', c, re.IGNORECASE):
                auth.add("OAuth 2.0")
            if re.search(r'\b(session|cookiesession|sessionmaker)\b', c, re.IGNORECASE):
                auth.add("Session-Based Auth")
            if re.search(r'\b(api_key|x-api-key|apikey)\b', c, re.IGNORECASE):
                auth.add("API Key Headers")
        return auth

    def _detect_apis(self) -> Set[str]:
        apis = set()
        for f in self.files:
            c = self._read_file_safe(f)
            if "@app.get" in c or "@app.post" in c or "@router." in c or "app.route(" in c or "express.Router" in c:
                apis.add("REST API Endpoints")
            if "graphql" in c.lower() or "schema.graphql" in f:
                apis.add("GraphQL API")
            if "websocket" in c.lower() or "socket.io" in c.lower():
                apis.add("WebSocket Streams")
        return apis

    def _detect_external_services(self) -> Set[str]:
        services = set()
        for f in self.files:
            c = self._read_file_safe(f)
            if "stripe" in c.lower():
                services.add("Stripe Payments")
            if "openai" in c.lower():
                services.add("OpenAI API")
            if "anthropic" in c.lower():
                services.add("Anthropic API")
            if "boto3" in c.lower() or "s3" in c.lower():
                services.add("AWS Cloud (S3/Boto3)")
            if "sendgrid" in c.lower():
                services.add("SendGrid Mailer")
        return services

    def _detect_sensitive_files(self) -> List[str]:
        sens = []
        for f in self.files:
            base = os.path.basename(f)
            if base in ('.env', '.env.local', '.env.production', 'credentials.json', 'id_rsa', 'key.pem', 'secrets.json'):
                sens.append(f)
        return sens

    def _read_file_safe(self, rel_path: str) -> str:
        try:
            full_path = os.path.join(self.project_path, rel_path)
            if not os.path.isfile(full_path):
                return ""
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(50000)
        except Exception:
            return ""
