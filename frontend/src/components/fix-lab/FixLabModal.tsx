"use client";

import React, { useState } from "react";
import { Vulnerability, FixProposal, FixSimulationResult } from "@/lib/types";
import { simulateFix, verifyAndApplyFix } from "@/lib/api";
import {
  Wrench,
  ShieldCheck,
  AlertTriangle,
  Play,
  CheckCircle2,
  X,
  FileCode,
  Zap,
  Sparkles,
  ArrowRight
} from "lucide-react";

interface FixLabModalProps {
  vulnerability: Vulnerability | null;
  onClose: () => void;
  onFixApplied: (vulnId: string, newScore: number) => void;
}

export const FixLabModal: React.FC<FixLabModalProps> = ({
  vulnerability,
  onClose,
  onFixApplied
}) => {
  const [isSimulating, setIsSimulating] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
  const [simulationResult, setSimulationResult] = useState<FixSimulationResult | null>(null);
  const [activeTab, setActiveTab] = useState<"diff" | "impact">("diff");

  if (!vulnerability) return null;

  const fix = vulnerability.fix;

  const handleSimulate = async () => {
    if (!fix) return;
    setIsSimulating(true);
    try {
      const res = await simulateFix(fix.id, vulnerability.id, fix.proposed_fix);
      setSimulationResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleApply = async () => {
    if (!fix) return;
    setIsApplying(true);
    try {
      const res = await verifyAndApplyFix(fix.id, vulnerability.id, fix.proposed_fix);
      onFixApplied(vulnerability.id, res.new_score || 67);
      onClose();
    } catch (err) {
      console.error(err);
    } finally {
      setIsApplying(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-graphite-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
      <div className="w-full max-w-4xl bg-graphite-900 border border-violet-500/40 rounded-2xl shadow-violet-glow flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-graphite-800 flex items-center justify-between bg-graphite-950/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-violet-500/10 border border-violet-500/30 text-violet-neon">
              <Wrench className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-mono font-bold text-white tracking-wide">
                  SECURITY FIX LAB
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet-500/20 text-violet-neon border border-violet-500/40 font-bold">
                  AUTONOMOUS REPAIR & RE-SCAN
                </span>
              </div>
              <p className="text-xs text-gray-400 font-mono mt-0.5">
                Target: {vulnerability.title} ({vulnerability.cwe}) in {vulnerability.file}:{vulnerability.line_start}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg border border-graphite-700 text-gray-400 hover:text-white hover:bg-graphite-800 transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 font-mono">
          {/* Side-by-side Code Comparison */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Original Vulnerable Code */}
            <div className="rounded-xl border border-rose-500/30 bg-graphite-950 overflow-hidden flex flex-col">
              <div className="px-3.5 py-2 bg-rose-950/30 border-b border-rose-500/20 flex items-center justify-between text-xs font-bold text-rose-400">
                <span>ORIGINAL VULNERABLE CODE</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300">
                  {vulnerability.severity}
                </span>
              </div>
              <pre className="p-4 text-xs text-rose-200 overflow-x-auto whitespace-pre-wrap leading-relaxed font-mono flex-1">
                {fix?.original_code || vulnerability.code_snippet}
              </pre>
            </div>

            {/* Proposed Secure Fix */}
            <div className="rounded-xl border border-emerald-500/30 bg-graphite-950 overflow-hidden flex flex-col">
              <div className="px-3.5 py-2 bg-emerald-950/30 border-b border-emerald-500/20 flex items-center justify-between text-xs font-bold text-emerald-400">
                <span>PROPOSED SECURE FIX</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                  CONFIDENCE {fix?.confidence || 96}%
                </span>
              </div>
              <pre className="p-4 text-xs text-emerald-200 overflow-x-auto whitespace-pre-wrap leading-relaxed font-mono flex-1">
                {fix?.proposed_fix}
              </pre>
            </div>
          </div>

          {/* Fix Insights: Why, What changed, Impact, Side effects */}
          {fix && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-4 rounded-xl border border-graphite-800 bg-graphite-950/50 space-y-3">
                <div>
                  <div className="text-cyan-neon font-bold uppercase mb-1">WHY THIS FIX?</div>
                  <p className="text-gray-300 leading-relaxed">{fix.why_this_fix}</p>
                </div>
                <div>
                  <div className="text-violet-neon font-bold uppercase mb-1">WHAT CHANGED?</div>
                  <p className="text-gray-300 leading-relaxed">{fix.what_changed}</p>
                </div>
              </div>

              <div className="p-4 rounded-xl border border-graphite-800 bg-graphite-950/50 space-y-3">
                <div>
                  <div className="text-emerald-400 font-bold uppercase mb-1">SECURITY IMPACT</div>
                  <p className="text-gray-300 leading-relaxed">{fix.security_impact}</p>
                </div>
                <div>
                  <div className="text-amber-400 font-bold uppercase mb-1">POSSIBLE SIDE EFFECTS</div>
                  <ul className="list-disc list-inside text-gray-300 space-y-1">
                    {fix.possible_side_effects.map((se, i) => (
                      <li key={i}>{se}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Fix Simulation Results Banner */}
          {simulationResult && (
            <div
              className={`p-4 rounded-xl border font-mono text-xs ${
                simulationResult.resolved
                  ? "bg-emerald-950/30 border-emerald-500/50 text-emerald-300 shadow-green-glow"
                  : "bg-rose-950/30 border-rose-500/50 text-rose-300"
              }`}
            >
              <div className="flex items-center space-x-2 font-bold mb-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>INDEPENDENT FIX SIMULATION RUN COMPLETED</span>
              </div>
              <p className="mb-3 leading-relaxed">{simulationResult.message}</p>

              {/* Before vs After Simulation Metrics */}
              <div className="grid grid-cols-2 gap-3 bg-graphite-950/70 p-3 rounded-lg border border-graphite-800 text-xs">
                <div>
                  <div className="text-gray-400 font-bold mb-1">BEFORE SIMULATION:</div>
                  <div className="text-rose-400">Critical: {simulationResult.before_critical}</div>
                  <div className="text-amber-400">High: {simulationResult.before_high}</div>
                  <div className="text-cyan-400">Medium: {simulationResult.before_medium}</div>
                </div>
                <div>
                  <div className="text-gray-400 font-bold mb-1">AFTER SIMULATION:</div>
                  <div className="text-emerald-400">
                    Critical: {simulationResult.after_critical} (-{simulationResult.before_critical - simulationResult.after_critical})
                  </div>
                  <div className="text-amber-300">High: {simulationResult.after_high}</div>
                  <div className="text-cyan-300">Medium: {simulationResult.after_medium}</div>
                </div>
              </div>

              {simulationResult.regressions.length > 0 && (
                <div className="mt-2 text-rose-400 font-bold">
                  ⚠ Regressions: {simulationResult.regressions.join(", ")}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-graphite-800 bg-graphite-950 flex items-center justify-between font-mono">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg border border-graphite-700 text-gray-400 hover:text-white text-xs transition-all"
          >
            REJECT / CLOSE
          </button>

          <div className="flex items-center space-x-3">
            <button
              onClick={handleSimulate}
              disabled={isSimulating || isApplying}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-neon text-xs font-bold transition-all disabled:opacity-50 shadow-cyan-glow"
            >
              <Play className="w-3.5 h-3.5 fill-cyan-neon" />
              <span>{isSimulating ? "SIMULATING SANDBOX RE-SCAN…" : "SIMULATE FIX IN SANDBOX"}</span>
            </button>

            <button
              onClick={handleApply}
              disabled={isApplying || isSimulating}
              className="flex items-center space-x-2 px-5 py-2 rounded-lg bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-400 hover:to-emerald-500 text-graphite-950 text-xs font-bold tracking-wide transition-all disabled:opacity-50 shadow-green-glow"
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>{isApplying ? "VERIFYING & APPLYING…" : "APPLY & VERIFY FIX"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
