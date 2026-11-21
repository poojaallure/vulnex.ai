-- VULNEX AI - Supabase PostgreSQL Schema
-- Run this script in the Supabase SQL Editor to initialize production tables.

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    last_scan_id TEXT,
    scan_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    project_name TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    status TEXT NOT NULL,
    score INTEGER NOT NULL,
    data_json JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    cwe TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    status TEXT NOT NULL,
    file TEXT NOT NULL,
    data_json JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS fixes (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    proposed_fix TEXT NOT NULL,
    status TEXT NOT NULL,
    data_json JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS research_runs (
    id TEXT PRIMARY KEY,
    system_name TEXT NOT NULL,
    data_json JSONB NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable Row Level Security (RLS)
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE fixes ENABLE ROW LEVEL SECURITY;
ALTER TABLE research_runs ENABLE ROW LEVEL SECURITY;

-- Allow read/write for service role & authenticated / anon client
CREATE POLICY "Allow public read access for demo" ON projects FOR SELECT USING (true);
CREATE POLICY "Allow public insert access for demo" ON projects FOR ALL USING (true);

CREATE POLICY "Allow public read access for scans" ON scans FOR SELECT USING (true);
CREATE POLICY "Allow public insert access for scans" ON scans FOR ALL USING (true);

CREATE POLICY "Allow public read access for vulnerabilities" ON vulnerabilities FOR SELECT USING (true);
CREATE POLICY "Allow public insert access for vulnerabilities" ON vulnerabilities FOR ALL USING (true);

CREATE POLICY "Allow public read access for fixes" ON fixes FOR SELECT USING (true);
CREATE POLICY "Allow public insert access for fixes" ON fixes FOR ALL USING (true);
