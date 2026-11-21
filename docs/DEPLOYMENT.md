# VULNEX AI - Deployment Guide

Unified deployment instructions for the integrated Vulnex.ai application.

## Architecture Overview

```
vulnex-ai/
├── frontend/          # Next.js 14 SOC dashboard (port 3000)
├── backend/           # FastAPI security scanning engine (port 8000)
├── demo-project/      # Vulnerable FastAPI scan target (port 8001)
├── shared/            # Shared types/constants (future)
├── docs/              # Deployment and operations documentation
├── .env.example       # Unified environment configuration
├── docker-compose.yml # Multi-service orchestration
├── Makefile           # Local development commands
└── README.md          # Project overview and feature documentation
```

## Service Communication

| Service | Port | Purpose |
|---------|------|---------|
| Frontend | 3000 | Next.js App Router SOC dashboard |
| Backend | 8000 | FastAPI scanning engine + REST APIs |
| Demo Project | 8001 | Vulnerable FastAPI app used as scan target |

- Frontend → Backend: `NEXT_PUBLIC_API_URL` (default `http://localhost:8000`)
- Backend → Supabase: `SUPABASE_URL` / `SUPABASE_SERVICE_ROLE_KEY` (optional, SQLite fallback)
- Backend → Gemini AI: `GEMINI_API_KEY` (optional, deterministic fallback used if absent)
- Backend ↔ Demo Project: No direct runtime coupling; demo-project is a scan target uploaded as `.zip`

## Prerequisites

- Python 3.11+
- Node.js 18+ and npm
- Docker & Docker Compose (for containerized deployment)

## Local Development

### Option 1: Makefile (recommended)

```bash
# 1. Copy environment template
cp .env.example .env
# Edit .env with your values (GEMINI_API_KEY, SUPABASE_*, etc.)

# 2. Install dependencies
make install

# 3. Start all services
make run

# 4. Open http://localhost:3000 in your browser
```

### Option 2: Manual

```bash
# Terminal 1 - Backend
pip install -r backend/requirements.txt
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 - Frontend
cd frontend && npm ci
cd frontend && npm run dev

# Terminal 3 - Demo project (optional scan target)
cd demo-project && python -m uvicorn app:app --host 0.0.0.0 --port 8001
```

### Option 3: Docker Compose

```bash
# 1. Copy environment template
cp .env.example .env
# Edit .env with your values

# 2. Start all services
docker-compose up --build

# 3. Open http://localhost:3000 in your browser
# 4. Backend health: http://localhost:8000/api/health
# 5. Demo project: http://localhost:8001/api/users?username=test
```

## Production Deployment

The application is designed for decoupled multi-cloud deployment:

### Frontend (Vercel)

1. Import repository into Vercel
2. Set **Root Directory:** `frontend`
3. Set **Build Command:** `next build`
4. Add Environment Variable: `NEXT_PUBLIC_API_URL=https://your-backend.onrender.com`
5. Deploy

### Backend (Render)

1. Create a new **Web Service** on Render connected to your repository
2. **Build Command:** `pip install -r backend/requirements.txt`
3. **Start Command:** `python -m uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT`
4. Add Environment Variables:
   - `PORT`: `10000`
   - `GEMINI_API_KEY`: `<your-gemini-api-key>`
   - `SUPABASE_URL`: `https://<project-ref>.supabase.co`
   - `SUPABASE_ANON_KEY`: `<your-supabase-anon-key>`
   - `SUPABASE_SERVICE_ROLE_KEY`: `<your-supabase-service-role-key>`
   - `CORS_ORIGINS`: `https://your-frontend.vercel.app,http://localhost:3000`
   - `MAX_UPLOAD_SIZE_MB`: `50`
5. Deploy

### Database (Supabase)

1. Create a new Supabase project at supabase.com
2. Run `backend/supabase_schema.sql` in the SQL Editor
3. Copy Project URL, anon key, and service_role key to backend env

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | 8000 | Backend server port |
| `GEMINI_API_KEY` | No | (empty) | Google Gemini API key for AI reasoning |
| `SUPABASE_URL` | No | (empty) | Supabase project URL |
| `SUPABASE_ANON_KEY` | No | (empty) | Supabase anonymous key |
| `SUPABASE_SERVICE_ROLE_KEY` | No | (empty) | Supabase service role key (secret) |
| `CORS_ORIGINS` | No | localhost origins | Comma-separated allowed CORS origins |
| `MAX_UPLOAD_SIZE_MB` | No | 50 | Max ZIP upload size in MB |
| `NEXT_PUBLIC_API_URL` | No | http://localhost:8000 | Frontend → Backend API base URL |
| `STRIPE_LIVE_KEY` | No | REDACTED_PLACEHOLDER | Demo project Stripe key (env-based) |
| `DATABASE_URL` | No | (no password) | Demo project database URL (env-based) |

## Security

- All secrets are loaded from environment variables — no hardcoded credentials
- `.env` and all local environment files are gitignored
- Only `.env.example` is tracked in Git (placeholder values only)
- Demo project secrets (`STRIPE_LIVE_KEY`, `DATABASE_URL`) are now env-based
- CORS is configured to restrict origins in production (wildcard only in dev fallback)

## Testing

```bash
# Backend unit tests
make test

# Frontend lint/typecheck
make test-frontend

# Frontend production build
make build-frontend
```

## GitHub Repository

Repository: https://github.com/poojaallure/vulnex.ai

To push changes (non-force, preserving history):

```bash
git add .
git commit -m "your commit message"
git push origin main
```
