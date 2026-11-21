import sqlite3
from fastapi import FastAPI

admin_router = FastAPI()

@admin_router.get("/api/admin/export/all_users")
def export_all_users():
    # VULNERABLE: Sensitive administrative export missing authentication/role guard (CWE-306)
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    data = c.fetchall()
    conn.close()
    return {"exported_records": data}
