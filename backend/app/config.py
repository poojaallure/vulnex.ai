import os
from typing import List
from pydantic import BaseModel

def parse_cors_origins() -> List[str]:
    raw = os.getenv("CORS_ORIGINS", "")
    if raw.strip():
        return [o.strip() for o in raw.split(",") if o.strip()]
    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://vulnex-ai.vercel.app",
        "*"
    ]

class Settings(BaseModel):
    app_name: str = "VULNEX AI Engine"
    app_version: str = "1.0.0"
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    supabase_url: str = os.getenv("SUPABASE_URL", "")
    supabase_anon_key: str = os.getenv("SUPABASE_ANON_KEY", "")
    supabase_service_role_key: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    cors_origins: List[str] = parse_cors_origins()
    max_upload_size_mb: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))

settings = Settings()
