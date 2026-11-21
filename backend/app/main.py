from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .config import settings
from .api import (
    routes_projects,
    routes_scans,
    routes_vulnerabilities,
    routes_fixes,
    routes_copilot,
    routes_research
)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="VULNEX AI: AI builds software. VULNEX proves it is safe."
)

# Configure production CORS
has_wildcard = "*" in settings.cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if has_wildcard else settings.cors_origins,
    allow_origin_regex=r"https://.*\.vercel\.app" if not has_wildcard else None,
    allow_credentials=False if has_wildcard else True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(routes_projects.router)
app.include_router(routes_scans.router)
app.include_router(routes_vulnerabilities.router)
app.include_router(routes_fixes.router)
app.include_router(routes_copilot.router)
app.include_router(routes_research.router)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
        "engine": "VULNEX Security Engine",
        "gemini_enabled": bool(settings.gemini_api_key)
    }

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Security Engine Exception",
            "message": str(exc),
            "detail": "VULNEX encountered an unhandled exception. Deterministic fallback mode is available."
        }
    )

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=port, reload=False)
