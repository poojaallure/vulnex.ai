"use client";

import React from "react";
import { ResearchMetric } from "@/lib/types";
import { FlaskConical, BarChart3, ShieldCheck, CheckCircle2, TrendingUp, Clock, Target } from "lucide-react";

interface ResearchLabViewProps {
  metrics: ResearchMetric[];
}

export const ResearchLabView: React.FC<ResearchLabViewProps> = ({ metrics }) => {
  return (
    <div className="bg-graphite-900 border border-graphite-700/80 rounded-2xl p-6 font-mono relative overflow-hidden">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-6 border-b border-graphite-800 gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-lg font-bold text-white tracking-wide">
              AI SECURITY RESEARCH LAB
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/30 text-violet-neon font-bold">
              EMPIRICAL BENCHMARKS (25 SAMPLES)
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Controlled ground-truth evaluation comparing Traditional Static Scanners, Raw LLM Prompts, and VULNEX Hybrid.
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs text-cyan-neon font-semibold">
          <FlaskConical className="w-4 h-4 text-violet-neon" />
          <span>Research Methodology: N=25 Ground Truth</span>
        </div>
      </div>

      {/* Comparative Metrics Table */}
      <div className="overflow-x-auto rounded-xl border border-graphite-800 mb-8">
        <table className="w-full text-left text-xs">
          <thead className="bg-graphite-950 border-b border-graphite-800 text-gray-400 uppercase text-[10px]">
            <tr>
              <th className="p-3.5">Analysis Engine</th>
              <th className="p-3.5">Precision</th>
              <th className="p-3.5">Recall</th>
              <th className="p-3.5">F1 Score</th>
              <th className="p-3.5">False Positive Rate</th>
              <th className="p-3.5">Fix Success</th>
              <th className="p-3.5">Verification Rate</th>
              <th className="p-3.5">Avg Time (s)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-graphite-800">
            {metrics.map((m, idx) => {
              const isVulnex = m.system_name.includes("VULNEX");

              return (
                <tr
                  key={idx}
                  className={`transition-colors ${
                    isVulnex
                      ? "bg-cyan-500/10 font-bold text-cyan-neon"
                      : "bg-graphite-950/60 text-gray-300 hover:bg-graphite-800/50"
                  }`}
                >
                  <td className="p-3.5 font-bold flex items-center space-x-2">
                    {isVulnex && <ShieldCheck className="w-4 h-4 text-cyan-neon shrink-0" />}
                    <span>{m.system_name}</span>
                  </td>
                  <td className="p-3.5">{(m.precision * 100).toFixed(0)}%</td>
                  <td className="p-3.5">{(m.recall * 100).toFixed(0)}%</td>
                  <td className="p-3.5 font-bold text-white">{(m.f1_score * 100).toFixed(0)}%</td>
                  <td className={`p-3.5 ${m.false_positive_rate > 0.2 ? "text-rose-400" : "text-emerald-400"}`}>
                    {(m.false_positive_rate * 100).toFixed(0)}%
                  </td>
                  <td className="p-3.5">{(m.fix_success_rate * 100).toFixed(0)}%</td>
                  <td className="p-3.5 font-bold text-emerald-400">
                    {(m.verification_success_rate * 100).toFixed(0)}%
                  </td>
                  <td className="p-3.5 text-gray-400">{m.avg_analysis_time_sec}s</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Visual Bar Comparisons */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* F1 & Precision Bar */}
        <div className="p-4 rounded-xl border border-graphite-800 bg-graphite-950/70 space-y-4">
          <div className="flex items-center space-x-2 text-xs font-bold text-white">
            <Target className="w-4 h-4 text-cyan-neon" />
            <span>F1-SCORE BENCHMARK</span>
          </div>

          <div className="space-y-3 text-xs">
            {metrics.map((m, idx) => (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between text-[11px] text-gray-400">
                  <span className="truncate max-w-[240px]">{m.system_name}</span>
                  <span className="font-bold text-white">{(m.f1_score * 100).toFixed(0)}%</span>
                </div>
                <div className="h-2 rounded-full bg-graphite-800 overflow-hidden">
                  <div
                    className={`h-full ${
                      m.system_name.includes("VULNEX")
                        ? "bg-gradient-to-r from-cyan-500 to-cyan-neon shadow-cyan-glow"
                        : "bg-gray-600"
                    }`}
                    style={{ width: `${m.f1_score * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Verification Success Rate Bar */}
        <div className="p-4 rounded-xl border border-graphite-800 bg-graphite-950/70 space-y-4">
          <div className="flex items-center space-x-2 text-xs font-bold text-white">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>INDEPENDENT VERIFICATION SUCCESS RATE</span>
          </div>

          <div className="space-y-3 text-xs">
            {metrics.map((m, idx) => (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between text-[11px] text-gray-400">
                  <span className="truncate max-w-[240px]">{m.system_name}</span>
                  <span className="font-bold text-emerald-400">
                    {(m.verification_success_rate * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="h-2 rounded-full bg-graphite-800 overflow-hidden">
                  <div
                    className={`h-full ${
                      m.system_name.includes("VULNEX")
                        ? "bg-gradient-to-r from-emerald-500 to-emerald-400 shadow-green-glow"
                        : "bg-gray-600"
                    }`}
                    style={{ width: `${m.verification_success_rate * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
