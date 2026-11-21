"use client";

import React, { useEffect, useState } from "react";
import { CheckCircle2, Loader2, Circle, Shield, Terminal } from "lucide-react";

interface Step {
  id: string;
  name: string;
  detail: string;
}

const PIPELINE_STEPS: Step[] = [
  { id: "s1", name: "PROJECT INGESTION", detail: "Extracting archive safely & enforcing Zip-Slip defenses" },
  { id: "s2", name: "ARCHITECTURE DISCOVERY", detail: "Mapping frameworks, database sinks, and trust perimeters" },
  { id: "s3", name: "PYTHON AST & STRUCTURAL ANALYSIS", detail: "Tracing data flow from untrusted sources to raw execute sinks" },
  { id: "s4", name: "SEMGREP STATIC CODE ANALYSIS", detail: "Running cross-language taint rules & AST signatures" },
  { id: "s5", name: "GITLEAKS & ENTROPY SECRET DETECTION", detail: "Detecting live credentials and API keys with Shannon entropy" },
  { id: "s6", name: "OSV-SCANNER SUPPLY CHAIN ANALYSIS", detail: "Cross-referencing dependencies with authoritative CVE databases" },
  { id: "s7", name: "AI CONTEXTUAL REASONING", detail: "Synthesizing code architecture, evidence chains, and attack vectors" },
  { id: "s8", name: "INDEPENDENT FIX SIMULATION & VERIFICATION", detail: "Running isolated sandboxed re-scan & regression radar" }
];

interface ScanPipelineProgressProps {
  onComplete?: () => void;
  speedMs?: number;
}

export const ScanPipelineProgress: React.FC<ScanPipelineProgressProps> = ({
  onComplete,
  speedMs = 700
}) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  useEffect(() => {
    if (currentStepIndex < PIPELINE_STEPS.length) {
      const timer = setTimeout(() => {
        setCurrentStepIndex((prev) => prev + 1);
      }, speedMs);
      return () => clearTimeout(timer);
    } else {
      if (onComplete) {
        const finishTimer = setTimeout(onComplete, 400);
        return () => clearTimeout(finishTimer);
      }
    }
  }, [currentStepIndex, speedMs, onComplete]);

  const progressPct = Math.min(100, Math.round(((currentStepIndex) / PIPELINE_STEPS.length) * 100));

  return (
    <div className="fixed inset-0 bg-graphite-950/85 backdrop-blur-xl z-50 flex items-center justify-center p-4">
      <div className="w-full max-w-xl bg-graphite-900 border border-cyan-500/30 rounded-2xl p-6 shadow-cyan-glow relative overflow-hidden">
        {/* Top Scanline effect */}
        <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-cyan-neon to-transparent animate-pulse" />

        <div className="flex items-center justify-between mb-6 pb-4 border-b border-graphite-700/80">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-neon">
              <Terminal className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h3 className="font-mono text-base font-bold text-white tracking-wide">
                VULNEX SECURITY PIPELINE RUNNING
              </h3>
              <p className="text-xs text-gray-400 font-mono">
                Multimodal static analysis, AST verification & AI reasoning
              </p>
            </div>
          </div>
          <span className="font-mono text-cyan-neon text-sm font-bold">{progressPct}%</span>
        </div>

        {/* Progress Bar */}
        <div className="w-full h-1.5 bg-graphite-800 rounded-full mb-6 overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 via-cyan-neon to-violet-500 transition-all duration-300"
            style={{ width: `${progressPct}%` }}
          />
        </div>

        {/* Pipeline Step List */}
        <div className="space-y-3 font-mono text-xs">
          {PIPELINE_STEPS.map((step, idx) => {
            const isFinished = idx < currentStepIndex;
            const isCurrent = idx === currentStepIndex;

            return (
              <div
                key={step.id}
                className={`flex items-start justify-between p-2.5 rounded-lg border transition-all ${
                  isCurrent
                    ? "bg-cyan-500/10 border-cyan-500/40 text-cyan-neon shadow-cyan-glow"
                    : isFinished
                    ? "bg-graphite-850/60 border-graphite-700/40 text-gray-300"
                    : "bg-transparent border-transparent text-gray-600"
                }`}
              >
                <div className="flex items-start space-x-3">
                  <div className="mt-0.5">
                    {isFinished ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : isCurrent ? (
                      <Loader2 className="w-4 h-4 text-cyan-neon animate-spin" />
                    ) : (
                      <Circle className="w-4 h-4 text-graphite-600" />
                    )}
                  </div>
                  <div>
                    <div className="font-semibold tracking-wide">{step.name}</div>
                    <div className="text-[11px] text-gray-400 mt-0.5">{step.detail}</div>
                  </div>
                </div>

                <div className="text-[11px] font-bold">
                  {isFinished ? "COMPLETE" : isCurrent ? "ACTIVE" : "QUEUED"}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
