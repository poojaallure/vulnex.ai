"use client";

import React, { useState } from "react";
import { AttackPath, AttackPathNode } from "@/lib/types";
import {
  GitCommit,
  ShieldAlert,
  ArrowRight,
  Database,
  Lock,
  Terminal,
  ExternalLink,
  Flame,
  Radio,
  FileCode
} from "lucide-react";

interface AttackPathVisualizerProps {
  attackPaths: AttackPath[];
}

export const AttackPathVisualizer: React.FC<AttackPathVisualizerProps> = ({ attackPaths }) => {
  const [selectedPathIndex, setSelectedPathIndex] = useState(0);
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null);

  if (!attackPaths || attackPaths.length === 0) {
    return (
      <div className="p-8 text-center bg-graphite-900 border border-graphite-800 rounded-2xl text-gray-400 font-mono text-sm">
        No active attack paths identified in scanned perimeter.
      </div>
    );
  }

  const currentPath = attackPaths[selectedPathIndex] || attackPaths[0];

  const getNodeColor = (type: string) => {
    switch (type) {
      case "INPUT":
        return "border-cyan-400 bg-cyan-950/40 text-cyan-300";
      case "TRUST_BOUNDARY":
        return "border-amber-400 bg-amber-950/40 text-amber-300";
      case "VULNERABLE_COMPONENT":
        return "border-rose-500 bg-rose-950/50 text-rose-300 shadow-red-glow";
      case "DATABASE":
        return "border-violet-400 bg-violet-950/40 text-violet-300";
      case "SENSITIVE_RESOURCE":
        return "border-rose-400 bg-rose-900/30 text-rose-200";
      case "EXTERNAL_SERVICE":
        return "border-emerald-400 bg-emerald-950/40 text-emerald-300";
      default:
        return "border-graphite-600 bg-graphite-800 text-gray-300";
    }
  };

  return (
    <div className="bg-graphite-900 border border-graphite-700/80 rounded-2xl p-6 relative overflow-hidden">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-6 border-b border-graphite-800 gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-lg font-mono font-bold text-white tracking-wide">
              AI ATTACK PATH MAP
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400">
              DEFENSIVE THREAT FLOW
            </span>
          </div>
          <p className="text-xs text-gray-400 font-mono mt-1">
            Simulates potential lateral traversal stages from ingress input through trust boundaries to database sinks.
          </p>
        </div>

        {/* Path Selector Tabs */}
        <div className="flex flex-wrap gap-2">
          {attackPaths.map((p, idx) => (
            <button
              key={p.id}
              onClick={() => {
                setSelectedPathIndex(idx);
                setActiveNodeId(null);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all border ${
                selectedPathIndex === idx
                  ? "bg-cyan-500/15 border-cyan-500 text-cyan-neon shadow-cyan-glow font-bold"
                  : "bg-graphite-950 border-graphite-800 text-gray-400 hover:text-white"
              }`}
            >
              Path #{idx + 1}
            </button>
          ))}
        </div>
      </div>

      {/* Path Title & Narrative Banner */}
      <div className="mb-6 p-4 rounded-xl border border-rose-500/30 bg-rose-950/20 font-mono">
        <div className="flex items-center space-x-2 text-rose-400 font-bold text-sm mb-1.5">
          <Flame className="w-4 h-4 text-rose-500" />
          <span>{currentPath.title}</span>
        </div>
        <p className="text-xs text-gray-300 leading-relaxed">{currentPath.narrative}</p>
      </div>

      {/* Interactive Step-by-Step Graph Canvas */}
      <div className="bg-graphite-950/90 border border-graphite-800 rounded-xl p-6 overflow-x-auto min-h-[220px] flex items-center">
        <div className="flex items-center space-x-3 mx-auto">
          {currentPath.nodes.map((node, index) => {
            const isLast = index === currentPath.nodes.length - 1;
            const isSelected = activeNodeId === node.id;
            const correspondingEdge = currentPath.edges.find((e) => e.source === node.id);

            return (
              <React.Fragment key={node.id}>
                {/* Node Box */}
                <div
                  onClick={() => setActiveNodeId(node.id)}
                  className={`min-w-[170px] max-w-[210px] p-3.5 rounded-xl border cursor-pointer transition-all duration-200 select-none ${getNodeColor(
                    node.type
                  )} ${
                    isSelected
                      ? "ring-2 ring-cyan-neon scale-105 shadow-cyan-glow"
                      : "hover:scale-102"
                  }`}
                >
                  <div className="flex items-center justify-between text-[10px] font-mono uppercase mb-1 text-gray-400">
                    <span>Stage {index + 1}</span>
                    <span className="font-bold">{node.type.replace("_", " ")}</span>
                  </div>
                  <div className="font-mono font-bold text-xs text-white mb-1 truncate">
                    {node.label}
                  </div>
                  <div className="text-[11px] text-gray-300 line-clamp-2 leading-tight">
                    {node.description}
                  </div>
                </div>

                {/* Connecting Edge Arrow */}
                {!isLast && (
                  <div className="flex flex-col items-center justify-center px-1">
                    <div className="text-[9px] font-mono text-cyan-400/90 whitespace-nowrap mb-1">
                      {correspondingEdge?.label || "flows to"}
                    </div>
                    <div className="flex items-center">
                      <div className="w-8 h-[2px] bg-gradient-to-r from-cyan-500 to-rose-500" />
                      <ArrowRight className="w-4 h-4 text-rose-400 -ml-1 shrink-0 animate-pulse" />
                    </div>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Node Inspector Callout */}
      {activeNodeId && (
        <div className="mt-4 p-4 rounded-xl border border-cyan-500/30 bg-graphite-950 font-mono text-xs">
          <div className="text-cyan-neon font-bold mb-1">
            STAGE TELEMETRY: {currentPath.nodes.find((n) => n.id === activeNodeId)?.label}
          </div>
          <p className="text-gray-300 leading-relaxed">
            {currentPath.nodes.find((n) => n.id === activeNodeId)?.description}
          </p>
        </div>
      )}
    </div>
  );
};
