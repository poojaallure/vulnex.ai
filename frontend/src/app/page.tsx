"use client";

import React, { useState, useEffect } from "react";
import {
  ScanResult,
  Vulnerability,
  TimelineEvent,
  ResearchMetric
} from "@/lib/types";
import {
  runDemoScan,
  uploadZipAndScan,
  fetchTimeline,
  fetchResearchMetrics
} from "@/lib/api";
import { INITIAL_DEMO_SCAN, DEMO_TIMELINE, DEMO_RESEARCH_METRICS } from "@/lib/demoData";
import { Topbar } from "@/components/layout/Topbar";
import { Sidebar, TabType } from "@/components/layout/Sidebar";
import { ScanPipelineProgress } from "@/components/scan/ScanPipelineProgress";
import { SecurityDNAConstellation } from "@/components/dna/SecurityDNAConstellation";
import { AttackPathVisualizer } from "@/components/attack-path/AttackPathVisualizer";
import { FixLabModal } from "@/components/fix-lab/FixLabModal";
import { SecurityRadarChart } from "@/components/radar/SecurityRadarChart";
import { SecurityPassportCard } from "@/components/passport/SecurityPassportCard";
import { SecurityTimeMachine } from "@/components/timeline/SecurityTimeMachine";
import { ResearchLabView } from "@/components/research/ResearchLabView";
import { SecurityCopilotDrawer } from "@/components/copilot/SecurityCopilotDrawer";
import { EvidenceChainView } from "@/components/scan/EvidenceChainView";

import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Play,
  Upload,
  ArrowRight,
  Sparkles,
  Dna,
  GitBranch,
  Wrench,
  History,
  FlaskConical,
  Award,
  ChevronRight,
  FileCode,
  Zap,
  Info,
  ExternalLink,
  Flame,
  Terminal,
  X
} from "lucide-react";

export default function Home() {
  const [inDashboard, setInDashboard] = useState(false);
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const [isBeginnerMode, setIsBeginnerMode] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [currentScan, setCurrentScan] = useState<ScanResult>(INITIAL_DEMO_SCAN);
  const [timeline, setTimeline] = useState<TimelineEvent[]>(DEMO_TIMELINE);
  const [researchMetrics, setResearchMetrics] = useState<ResearchMetric[]>(DEMO_RESEARCH_METRICS);

  // Modals & Drawers
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [selectedVulnForFix, setSelectedVulnForFix] = useState<Vulnerability | null>(null);
  const [inspectedVulnId, setInspectedVulnId] = useState<string | null>("vuln_sqli_1");
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [uploadFile, setUploadFile] = useState<File | null>(null);

  useEffect(() => {
    // Attempt fetching live timeline & metrics from backend
    fetchTimeline(currentScan.project_id)
      .then(setTimeline)
      .catch(() => {});
    fetchResearchMetrics()
      .then(setResearchMetrics)
      .catch(() => {});
  }, [currentScan.project_id]);

  const handleRunDemo = async () => {
    setIsScanning(true);
  };

  const handleScanPipelineComplete = async () => {
    setIsScanning(false);
    try {
      const res = await runDemoScan();
      setCurrentScan(res);
    } catch {
      setCurrentScan(INITIAL_DEMO_SCAN);
    }
    setInDashboard(true);
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadFile) return;

    setIsUploadModalOpen(false);
    setIsScanning(true);

    try {
      const res = await uploadZipAndScan(uploadFile, uploadFile.name.replace(".zip", ""));
      setCurrentScan(res);
      setInDashboard(true);
    } catch (err: any) {
      alert(`Upload scan error: ${err.message || "Failed to scan archive"}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleFixApplied = (vulnId: string, newScore: number) => {
    setCurrentScan((prev) => {
      const updatedVulns = prev.vulnerabilities.map((v) =>
        v.id === vulnId ? { ...v, status: "FIX VERIFIED" as const } : v
      );
      return {
        ...prev,
        score_breakdown: {
          ...prev.score_breakdown,
          score: newScore,
        },
        passport: {
          ...prev.passport,
          security_score: newScore,
          verified_fixes_count: prev.passport.verified_fixes_count + 1,
        },
        vulnerabilities: updatedVulns,
      };
    });
  };

  // Helper counts
  const critCount = currentScan.vulnerabilities.filter(
    (v) => v.severity === "CRITICAL" && v.status !== "FIX VERIFIED" && v.status !== "RESOLVED"
  ).length;
  const highCount = currentScan.vulnerabilities.filter(
    (v) => v.severity === "HIGH" && v.status !== "FIX VERIFIED" && v.status !== "RESOLVED"
  ).length;
  const verifiedCount = currentScan.vulnerabilities.filter(
    (v) => v.status === "FIX VERIFIED" || v.status === "RESOLVED"
  ).length;
  const unresolvedCount = currentScan.vulnerabilities.filter(
    (v) => v.status !== "FIX VERIFIED" && v.status !== "RESOLVED"
  ).length;

  // ----------------------------------------------------
  // 1. LANDING SCREEN (If not yet navigated to dashboard)
  // ----------------------------------------------------
  if (!inDashboard) {
    return (
      <main className="min-h-screen bg-graphite-950 flex flex-col justify-between relative overflow-hidden font-mono">
        {/* Animated Cyberpunk Background Grid & Glows */}
        <div className="absolute inset-0 pointer-events-none opacity-20 bg-[radial-gradient(#00f0ff_1px,transparent_1px)] [background-size:32px_32px]" />
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-violet-500/10 rounded-full blur-[120px] pointer-events-none" />

        {/* Minimal Navbar */}
        <header className="p-6 flex items-center justify-between border-b border-graphite-800/60 backdrop-blur-sm z-10">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-neon shadow-cyan-glow">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <span className="font-bold text-lg tracking-wider text-white">VULNEX AI</span>
          </div>

          <div className="flex items-center space-x-3 text-xs">
            <button
              onClick={() => {
                setInDashboard(true);
                setActiveTab("research");
              }}
              className="text-gray-400 hover:text-cyan-neon transition-colors"
            >
              Research Lab
            </button>
            <span className="text-graphite-700">|</span>
            <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-neon border border-cyan-500/30 text-[10px]">
              AI Verification SOC
            </span>
          </div>
        </header>

        {/* Hero Section */}
        <section className="flex-1 flex flex-col items-center justify-center text-center px-4 py-12 z-10 max-w-4xl mx-auto">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-neon text-xs mb-8 shadow-cyan-glow">
            <Sparkles className="w-3.5 h-3.5" />
            <span>AI BUILDS SOFTWARE. VULNEX PROVES IT IS SAFE.</span>
          </div>

          <h1 className="text-4xl sm:text-6xl md:text-7xl font-black text-white tracking-tight leading-none mb-6">
            AI BUILDS. <br />
            <span className="bg-gradient-to-r from-cyan-neon via-cyan-400 to-violet-400 bg-clip-text text-transparent">
              VULNEX VERIFIES.
            </span>
          </h1>

          <p className="text-gray-400 text-sm sm:text-base max-w-2xl mb-10 leading-relaxed font-sans">
            Don&apos;t trust AI-generated code blindly. VULNEX performs structural AST tracing,
            discovers Security DNA, maps exploit paths, generates autonomous repairs, and
            <span className="text-cyan-neon font-semibold"> independently proves they work</span> in a sandboxed re-scan.
          </p>

          {/* Primary Action Buttons */}
          <div className="flex flex-col sm:flex-row items-center gap-4 w-full justify-center">
            <button
              onClick={() => handleRunDemo()}
              className="w-full sm:w-auto px-8 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-400 hover:to-cyan-500 text-graphite-950 font-bold text-sm tracking-wide transition-all shadow-cyan-glow flex items-center justify-center space-x-2.5"
            >
              <Play className="w-4 h-4 fill-graphite-950" />
              <span>LAUNCH DEMO APPLICATION</span>
            </button>

            <button
              onClick={() => setIsUploadModalOpen(true)}
              className="w-full sm:w-auto px-8 py-3.5 rounded-xl border border-graphite-700 hover:border-cyan-neon bg-graphite-900/80 text-white font-bold text-sm tracking-wide transition-all flex items-center justify-center space-x-2"
            >
              <Upload className="w-4 h-4 text-cyan-neon" />
              <span>SCAN PROJECT ARCHIVE (.ZIP)</span>
            </button>

            <button
              onClick={() => {
                setInDashboard(true);
                setActiveTab("research");
              }}
              className="w-full sm:w-auto px-6 py-3.5 rounded-xl border border-violet-500/40 hover:border-violet-400 bg-violet-500/10 text-violet-neon font-bold text-sm tracking-wide transition-all flex items-center justify-center space-x-2 shadow-violet-glow"
            >
              <FlaskConical className="w-4 h-4" />
              <span>RESEARCH LAB</span>
            </button>
          </div>

          {/* Key Feature Badges */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-16 text-left w-full">
            <div className="p-3 rounded-lg border border-graphite-800 bg-graphite-900/40 text-xs">
              <div className="text-cyan-neon font-bold mb-0.5">SECURITY DNA</div>
              <p className="text-gray-400 text-[11px]">Interactive architectural constellation mapping.</p>
            </div>
            <div className="p-3 rounded-lg border border-graphite-800 bg-graphite-900/40 text-xs">
              <div className="text-rose-400 font-bold mb-0.5">ATTACK PATH MAP</div>
              <p className="text-gray-400 text-[11px]">Multi-stage defensive threat flow simulation.</p>
            </div>
            <div className="p-3 rounded-lg border border-graphite-800 bg-graphite-900/40 text-xs">
              <div className="text-emerald-400 font-bold mb-0.5">AI FIX LAB</div>
              <p className="text-gray-400 text-[11px]">Sandboxed re-scan & regression verification.</p>
            </div>
            <div className="p-3 rounded-lg border border-graphite-800 bg-graphite-900/40 text-xs">
              <div className="text-violet-neon font-bold mb-0.5">HALLUCINATION GUARD</div>
              <p className="text-gray-400 text-[11px]">Eliminates LLM false alarms via AST proof.</p>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className="p-6 text-center text-xs text-gray-500 border-t border-graphite-800/60 z-10">
          VULNEX AI Security Platform • Hackathon Master Release • Next.js + FastAPI + AST + Semgrep + Gitleaks + OSV-Scanner + Gemini
        </footer>

        {/* Upload Modal on Landing */}
        {isUploadModalOpen && renderUploadModal()}

        {/* Animated Scan Progress Overlay */}
        {isScanning && <ScanPipelineProgress onComplete={handleScanPipelineComplete} />}
      </main>
    );
  }

  // ----------------------------------------------------
  // 2. MAIN SOC OPERATIONS DASHBOARD
  // ----------------------------------------------------
  return (
    <div className="min-h-screen bg-graphite-950 text-white flex flex-col font-sans select-none">
      {/* Topbar */}
      <Topbar
        projectName={currentScan.project_name}
        isBeginnerMode={isBeginnerMode}
        setIsBeginnerMode={setIsBeginnerMode}
        onOpenUpload={() => setIsUploadModalOpen(true)}
        onRunDemo={handleRunDemo}
        onOpenCopilot={() => setIsCopilotOpen(true)}
        isScanning={isScanning}
      />

      {/* Main Layout: Sidebar + Content Area */}
      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          openCriticalCount={critCount}
          unresolvedCount={unresolvedCount}
          regressionsCount={currentScan.regressions_detected.length}
          onOpenCopilot={() => setIsCopilotOpen(true)}
        />

        {/* Content Body */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Tab 1: OVERVIEW */}
          {activeTab === "overview" && (
            <div className="space-y-6">
              {/* Score & Threat Overview Row */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* VULNEX Security Score Gauge Card */}
                <div className="lg:col-span-5 bg-graphite-900 border border-graphite-700/80 rounded-2xl p-6 font-mono relative overflow-hidden flex flex-col justify-between">
                  <div className="flex items-center justify-between pb-3 border-b border-graphite-800 mb-4">
                    <div className="flex items-center space-x-2">
                      <ShieldCheck className="w-5 h-5 text-cyan-neon" />
                      <h3 className="text-sm font-bold tracking-wide">VULNEX SECURITY SCORE</h3>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                        currentScan.score_breakdown.score >= 80
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                          : currentScan.score_breakdown.score >= 60
                          ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                          : "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                      }`}
                    >
                      {currentScan.passport.risk_level} RISK
                    </span>
                  </div>

                  <div className="flex items-center justify-center my-2">
                    <div className="relative flex items-center justify-center">
                      {/* Circular Gauge */}
                      <svg className="w-48 h-48 transform -rotate-90">
                        <circle
                          cx="96"
                          cy="96"
                          r="80"
                          className="stroke-graphite-800 stroke-[12] fill-none"
                        />
                        <circle
                          cx="96"
                          cy="96"
                          r="80"
                          className={`stroke-[12] fill-none transition-all duration-1000 ${
                            currentScan.score_breakdown.score >= 80
                              ? "stroke-emerald-400 shadow-green-glow"
                              : currentScan.score_breakdown.score >= 60
                              ? "stroke-amber-400"
                              : "stroke-rose-500 shadow-red-glow"
                          }`}
                          strokeDasharray={2 * Math.PI * 80}
                          strokeDashoffset={
                            2 * Math.PI * 80 * (1 - currentScan.score_breakdown.score / 100)
                          }
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="absolute text-center">
                        <span className="text-5xl font-black text-white">
                          {currentScan.score_breakdown.score}
                        </span>
                        <div className="text-[11px] text-gray-400">OUT OF 100</div>
                      </div>
                    </div>
                  </div>

                  {/* Transparent Score Audit Breakdown */}
                  <div className="mt-4 pt-3 border-t border-graphite-800">
                    <div className="text-[11px] text-gray-400 font-bold mb-1.5 uppercase">
                      Transparent Score Audit Breakdown:
                    </div>
                    <div className="space-y-1 text-xs">
                      {currentScan.score_breakdown.audit_trail.slice(0, 3).map((item, i) => (
                        <div key={i} className="text-gray-300 flex items-start space-x-1.5">
                          <span className="text-rose-400 font-bold">•</span>
                          <span>{item}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Threat Stats Cards */}
                <div className="lg:col-span-7 grid grid-cols-2 sm:grid-cols-3 gap-4">
                  <div className="p-4 rounded-xl border border-rose-500/30 bg-graphite-900 flex flex-col justify-between font-mono">
                    <div className="text-xs text-gray-400 uppercase">Critical Risks</div>
                    <div className="text-3xl font-black text-rose-400 my-2">{critCount}</div>
                    <div className="text-[11px] text-rose-300">Requires immediate fix</div>
                  </div>

                  <div className="p-4 rounded-xl border border-amber-500/30 bg-graphite-900 flex flex-col justify-between font-mono">
                    <div className="text-xs text-gray-400 uppercase">High Severity</div>
                    <div className="text-3xl font-black text-amber-400 my-2">{highCount}</div>
                    <div className="text-[11px] text-amber-300">Privilege & auth flaws</div>
                  </div>

                  <div className="p-4 rounded-xl border border-emerald-500/30 bg-graphite-900 flex flex-col justify-between font-mono">
                    <div className="text-xs text-gray-400 uppercase">Verified Fixes</div>
                    <div className="text-3xl font-black text-emerald-400 my-2">{verifiedCount}</div>
                    <div className="text-[11px] text-emerald-300">Re-scan validated</div>
                  </div>

                  <div className="p-4 rounded-xl border border-cyan-500/30 bg-graphite-900 flex flex-col justify-between font-mono">
                    <div className="text-xs text-gray-400 uppercase">Supply Chain</div>
                    <div className="text-3xl font-black text-cyan-neon my-2">
                      {currentScan.passport.dependency_health_pct}%
                    </div>
                    <div className="text-[11px] text-gray-400">Dependency health</div>
                  </div>

                  <div className="p-4 rounded-xl border border-violet-500/30 bg-graphite-900 flex flex-col justify-between font-mono">
                    <div className="text-xs text-gray-400 uppercase">Secrets Health</div>
                    <div className="text-3xl font-black text-violet-neon my-2">
                      {currentScan.passport.secret_health_pct}%
                    </div>
                    <div className="text-[11px] text-gray-400">Credential posture</div>
                  </div>

                  <div className="p-4 rounded-xl border border-graphite-700 bg-graphite-900 flex flex-col justify-between font-mono">
                    <div className="text-xs text-gray-400 uppercase">AI Confidence</div>
                    <div className="text-3xl font-black text-white my-2">
                      {currentScan.passport.ai_confidence_pct}%
                    </div>
                    <div className="text-[11px] text-cyan-neon">Hallucination Guarded</div>
                  </div>
                </div>
              </div>

              {/* Security Radar + DNA Preview Row */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                <div className="lg:col-span-5">
                  <SecurityRadarChart metrics={currentScan.radar} />
                </div>
                <div className="lg:col-span-7">
                  <SecurityDNAConstellation dna={currentScan.security_dna} />
                </div>
              </div>

              {/* Attack Path Preview */}
              <div>
                <AttackPathVisualizer
                  attackPaths={currentScan.vulnerabilities
                    .filter((v) => !!v.attack_path)
                    .map((v) => v.attack_path!)}
                />
              </div>
            </div>
          )}

          {/* Tab 2: SECURITY DNA */}
          {activeTab === "dna" && (
            <SecurityDNAConstellation dna={currentScan.security_dna} />
          )}

          {/* Tab 3: ATTACK PATHS */}
          {activeTab === "attack-paths" && (
            <AttackPathVisualizer
              attackPaths={currentScan.vulnerabilities
                .filter((v) => !!v.attack_path)
                .map((v) => v.attack_path!)}
            />
          )}

          {/* Tab 4: VULNERABILITIES */}
          {activeTab === "vulnerabilities" && renderVulnerabilitiesTab()}

          {/* Tab 5: FIX LAB */}
          {activeTab === "fix-lab" && (
            <div className="space-y-6">
              <div className="p-6 bg-graphite-900 border border-graphite-700/80 rounded-2xl font-mono">
                <div className="flex items-center space-x-2 text-violet-neon text-sm font-bold mb-2">
                  <Wrench className="w-5 h-5" />
                  <span>AI FIX LAB & SIMULATION ENVIRONMENT</span>
                </div>
                <p className="text-xs text-gray-400 leading-relaxed max-w-3xl">
                  Select any vulnerability below to open the side-by-side diff studio, run isolated
                  sandbox simulation re-scans, and verify that the security risk is truly resolved
                  without causing syntax errors or security regressions.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {currentScan.vulnerabilities.map((v) => (
                  <div
                    key={v.id}
                    className="p-5 rounded-2xl bg-graphite-900 border border-graphite-800 hover:border-violet-500/40 transition-all font-mono space-y-3"
                  >
                    <div className="flex items-center justify-between">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          v.severity === "CRITICAL"
                            ? "bg-rose-500/20 text-rose-400 border-rose-500/40"
                            : "bg-amber-500/20 text-amber-400 border-amber-500/40"
                        }`}
                      >
                        {v.severity}
                      </span>
                      <span className="text-[11px] text-cyan-neon font-bold">
                        {v.status}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-white">{v.title}</h4>
                    <div className="text-xs text-gray-400 truncate">
                      {v.file}:{v.line_start}
                    </div>

                    <button
                      onClick={() => setSelectedVulnForFix(v)}
                      className="w-full py-2 px-3 rounded-lg border border-violet-500/40 bg-violet-500/10 hover:bg-violet-500/20 text-violet-neon text-xs font-bold transition-all shadow-violet-glow flex items-center justify-center space-x-2"
                    >
                      <Wrench className="w-3.5 h-3.5" />
                      <span>OPEN FIX LAB FOR THIS ISSUE</span>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tab 6: TIME MACHINE */}
          {activeTab === "timeline" && (
            <SecurityTimeMachine
              timeline={timeline}
              activeRegressions={currentScan.regressions_detected}
            />
          )}

          {/* Tab 7: RESEARCH LAB */}
          {activeTab === "research" && <ResearchLabView metrics={researchMetrics} />}

          {/* Tab 8: SECURITY PASSPORT */}
          {activeTab === "passport" && <SecurityPassportCard passport={currentScan.passport} />}
        </main>
      </div>

      {/* Global Modals & Drawers */}
      {isUploadModalOpen && renderUploadModal()}

      {selectedVulnForFix && (
        <FixLabModal
          vulnerability={selectedVulnForFix}
          onClose={() => setSelectedVulnForFix(null)}
          onFixApplied={handleFixApplied}
        />
      )}

      {isScanning && <ScanPipelineProgress onComplete={handleScanPipelineComplete} />}

      <SecurityCopilotDrawer
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
        projectId={currentScan.project_id}
        scanId={currentScan.scan_id}
        isBeginnerMode={isBeginnerMode}
        activeVulnerabilityId={inspectedVulnId || undefined}
      />
    </div>
  );

  // ----------------------------------------------------
  // SUB-RENDER: Vulnerabilities Tab with Evidence Chains
  // ----------------------------------------------------
  function renderVulnerabilitiesTab() {
    const inspectedVuln =
      currentScan.vulnerabilities.find((v) => v.id === inspectedVulnId) ||
      currentScan.vulnerabilities[0];

    return (
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start font-mono">
        {/* Left List of Findings */}
        <div className="lg:col-span-5 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-graphite-800 text-xs text-gray-400">
            <span>DETECTED FINDINGS ({currentScan.vulnerabilities.length})</span>
            <span>Sorted by Severity</span>
          </div>

          <div className="space-y-2">
            {currentScan.vulnerabilities.map((v) => {
              const isSelected = inspectedVuln?.id === v.id;
              const isVerified = v.status === "FIX VERIFIED" || v.status === "RESOLVED";

              return (
                <div
                  key={v.id}
                  onClick={() => setInspectedVulnId(v.id)}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? "bg-graphite-900 border-cyan-neon shadow-cyan-glow"
                      : "bg-graphite-950/70 border-graphite-800 hover:border-graphite-700"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span
                      className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase ${
                        v.severity === "CRITICAL"
                          ? "bg-rose-500/20 text-rose-400 border-rose-500/30"
                          : "bg-amber-500/20 text-amber-400 border-amber-500/30"
                      }`}
                    >
                      {v.severity}
                    </span>

                    <span
                      className={`text-[10px] font-bold ${
                        isVerified ? "text-emerald-400" : "text-cyan-neon"
                      }`}
                    >
                      {v.status}
                    </span>
                  </div>

                  <h4 className="text-xs font-bold text-white truncate mb-1">{v.title}</h4>
                  <div className="flex items-center justify-between text-[11px] text-gray-400">
                    <span className="truncate max-w-[200px]">{v.file}:{v.line_start}</span>
                    <span>Conf: {v.confidence}%</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Detail Pane */}
        {inspectedVuln && (
          <div className="lg:col-span-7 bg-graphite-900 border border-graphite-700/80 rounded-2xl p-6 space-y-6">
            {/* Header info */}
            <div className="flex flex-col sm:flex-row sm:items-start justify-between pb-4 border-b border-graphite-800 gap-3">
              <div>
                <div className="flex items-center space-x-2 mb-1">
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                      inspectedVuln.severity === "CRITICAL"
                        ? "bg-rose-500/20 text-rose-400 border-rose-500/40"
                        : "bg-amber-500/20 text-amber-400 border-amber-500/40"
                    }`}
                  >
                    {inspectedVuln.severity}
                  </span>
                  <span className="text-xs text-gray-400">{inspectedVuln.cwe}</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-neon border border-cyan-500/30 font-bold">
                    {inspectedVuln.hallucination_status}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white">{inspectedVuln.title}</h3>
                <div className="text-xs text-cyan-neon mt-0.5">
                  Location: {inspectedVuln.file}:{inspectedVuln.line_start}
                </div>
              </div>

              <button
                onClick={() => setSelectedVulnForFix(inspectedVuln)}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-violet-600 to-violet-700 hover:from-violet-500 hover:to-violet-600 text-white text-xs font-bold tracking-wide shadow-violet-glow flex items-center space-x-1.5 self-start shrink-0"
              >
                <Wrench className="w-3.5 h-3.5" />
                <span>OPEN FIX LAB</span>
              </button>
            </div>

            {/* AI Explanation based on Mode */}
            <div className="p-4 rounded-xl border border-graphite-800 bg-graphite-950/70 space-y-2 text-xs">
              <div className="text-cyan-neon font-bold uppercase">
                {isBeginnerMode ? "BEGINNER EXPLANATION" : "SECURITY REASONING"}
              </div>
              <p className="text-gray-300 leading-relaxed font-sans text-xs">
                {isBeginnerMode
                  ? inspectedVuln.ai_explanation_beginner
                  : inspectedVuln.ai_explanation_technical}
              </p>
            </div>

            {/* Deterministic Multi-Stage Evidence Chain */}
            <EvidenceChainView evidenceChain={inspectedVuln.evidence_chain} />
          </div>
        )}
      </div>
    );
  }

  // ----------------------------------------------------
  // SUB-RENDER: Upload ZIP Modal
  // ----------------------------------------------------
  function renderUploadModal() {
    return (
      <div className="fixed inset-0 bg-graphite-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
        <div className="w-full max-w-md bg-graphite-900 border border-cyan-500/40 rounded-2xl p-6 shadow-cyan-glow relative font-mono">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-graphite-800">
            <h3 className="font-bold text-white text-sm">UPLOAD PROJECT ARCHIVE (.ZIP)</h3>
            <button
              onClick={() => setIsUploadModalOpen(false)}
              className="text-gray-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <form onSubmit={handleUploadSubmit} className="space-y-4">
            <div className="p-6 border-2 border-dashed border-graphite-700 hover:border-cyan-neon rounded-xl text-center bg-graphite-950/60 transition-all cursor-pointer">
              <Upload className="w-8 h-8 text-cyan-neon mx-auto mb-2" />
              <input
                type="file"
                accept=".zip"
                onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                className="hidden"
                id="zip-upload-input"
              />
              <label htmlFor="zip-upload-input" className="cursor-pointer">
                <div className="text-xs text-gray-300 font-bold mb-1">
                  {uploadFile ? uploadFile.name : "Choose or drag .zip project archive"}
                </div>
                <div className="text-[10px] text-gray-500">Max size: 50MB. Safe Zip-Slip sandbox.</div>
              </label>
            </div>

            <div className="flex items-center space-x-2 pt-2">
              <button
                type="submit"
                disabled={!uploadFile}
                className="flex-1 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-graphite-950 text-xs font-bold disabled:opacity-50 shadow-cyan-glow"
              >
                START VULNEX SCAN
              </button>
              <button
                type="button"
                onClick={() => {
                  setIsUploadModalOpen(false);
                  handleRunDemo();
                }}
                className="py-2 px-3 rounded-lg border border-violet-500/40 bg-violet-500/10 text-violet-neon text-xs font-bold"
              >
                Use Demo
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  }
}
