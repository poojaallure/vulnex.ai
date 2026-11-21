import sqlite3
import subprocess
from fastapi import FastAPI, Request

app = FastAPI(title="AI-Commerce API")

def get_db():
    conn = sqlite3.connect("database.db")
    return conn

@app.get("/api/users")
def get_user(username: str):
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABLE: Direct string interpolation into raw SQL query (CWE-89)
    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return {"users": results}

@app.post("/api/diagnostics/ping")
def ping_service(host: str):
    # VULNERABLE: Subprocess invocation with shell=True and user input (CWE-78)
    cmd = f"ping -c 1 {host}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    stdout, _ = proc.communicate()
    return {"output": stdout.decode("utf-8", errors="ignore")}
