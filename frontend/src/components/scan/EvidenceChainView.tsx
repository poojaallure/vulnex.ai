"use client";

import React, { useState } from "react";
import { EvidenceStep } from "@/lib/types";
import { ArrowDown, Code2, ChevronDown, ChevronRight, AlertCircle, FileText } from "lucide-react";

interface EvidenceChainViewProps {
  evidenceChain: EvidenceStep[];
}

export const EvidenceChainView: React.FC<EvidenceChainViewProps> = ({ evidenceChain }) => {
  const [expandedSteps, setExpandedSteps] = useState<Record<number, boolean>>({ 1: true });

  const toggleStep = (stepNum: number) => {
    setExpandedSteps((prev) => ({
      ...prev,
      [stepNum]: !prev[stepNum],
    }));
  };

  const getRoleBadge = (role: string) => {
    switch (role) {
      case "SOURCE":
        return "bg-cyan-500/20 text-cyan-300 border-cyan-500/30";
      case "PROPAGATION":
        return "bg-amber-500/20 text-amber-300 border-amber-500/30";
      case "SINK":
        return "bg-rose-500/20 text-rose-300 border-rose-500/30";
      case "SANITIZER":
        return "bg-emerald-500/20 text-emerald-300 border-emerald-500/30";
      default:
        return "bg-graphite-800 text-gray-300 border-graphite-700";
    }
  };

  return (
    <div className="space-y-3 font-mono">
      <div className="flex items-center justify-between text-xs text-gray-400 mb-1">
        <span className="font-bold text-white uppercase tracking-wider">
          DETERMINISTIC EVIDENCE CHAIN ({evidenceChain.length} STAGES)
        </span>
        <span>AST & Static Data-Flow Proof</span>
      </div>

      <div className="space-y-2">
        {evidenceChain.map((step, idx) => {
          const isExpanded = !!expandedSteps[step.step];
          const isLast = idx === evidenceChain.length - 1;

          return (
            <div key={step.step} className="relative">
              <div
                onClick={() => toggleStep(step.step)}
                className={`p-3 rounded-xl border transition-all cursor-pointer ${
                  isExpanded
                    ? "bg-graphite-900 border-cyan-500/40 shadow-cyan-glow"
                    : "bg-graphite-950/80 border-graphite-800 hover:border-graphite-700"
                }`}
              >
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center space-x-2.5">
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-cyan-neon" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-gray-500" />
                    )}
                    <span className="font-bold text-white">Stage {step.step}:</span>
                    <span className="text-cyan-neon truncate max-w-xs md:max-w-md">
                      {step.file}:{step.line}
                    </span>
                  </div>

                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${getRoleBadge(
                      step.role
                    )}`}
                  >
                    {step.role}
                  </span>
                </div>

                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-graphite-800 space-y-2">
                    <p className="text-xs text-gray-300 leading-relaxed">{step.description}</p>
                    <div className="p-2.5 rounded-lg bg-graphite-950 border border-graphite-800 text-xs text-cyan-200 overflow-x-auto whitespace-pre-wrap">
                      <code>{step.code}</code>
                    </div>
                  </div>
                )}
              </div>

              {!isLast && (
                <div className="flex justify-center py-1">
                  <ArrowDown className="w-3.5 h-3.5 text-graphite-600" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
