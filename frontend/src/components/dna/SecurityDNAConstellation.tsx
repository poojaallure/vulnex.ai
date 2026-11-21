"use client";

import React, { useState } from "react";
import { SecurityDNA, SecurityDNANode } from "@/lib/types";
import {
  ShieldAlert,
  Server,
  Lock,
  Database,
  Key,
  Globe,
  Package,
  FileCode,
  Info,
  CheckCircle,
  AlertTriangle
} from "lucide-react";

interface SecurityDNAConstellationProps {
  dna: SecurityDNA;
}

export const SecurityDNAConstellation: React.FC<SecurityDNAConstellationProps> = ({ dna }) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string>("node_dna_app");

  const selectedNode = dna.nodes.find((n) => n.id === selectedNodeId) || dna.nodes[0];

  const getNodeCoordinates = (category: string) => {
    switch (category) {
      case "APP":
        return { x: 350, y: 220 }; // Central hub
      case "AUTH":
        return { x: 350, y: 70 }; // Top
      case "API":
        return { x: 120, y: 220 }; // Left
      case "DATABASE":
        return { x: 580, y: 220 }; // Right
      case "SECRET":
        return { x: 230, y: 350 }; // Bottom-left
      case "EXTERNAL_API":
        return { x: 470, y: 350 }; // Bottom-right
      case "DEPENDENCY":
        return { x: 350, y: 410 }; // Bottom center
      default:
        return { x: 350, y: 220 };
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "APP":
        return Server;
      case "AUTH":
        return Lock;
      case "API":
        return Globe;
      case "DATABASE":
        return Database;
      case "SECRET":
        return Key;
      case "EXTERNAL_API":
        return Globe;
      case "DEPENDENCY":
        return Package;
      default:
        return FileCode;
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case "CRITICAL":
        return "text-rose-400 stroke-rose-500 fill-rose-950/60";
      case "HIGH":
        return "text-amber-400 stroke-amber-500 fill-amber-950/60";
      case "MEDIUM":
        return "text-cyan-400 stroke-cyan-500 fill-cyan-950/60";
      default:
        return "text-emerald-400 stroke-emerald-500 fill-emerald-950/60";
    }
  };

  return (
    <div className="bg-graphite-900 border border-graphite-700/80 rounded-2xl p-6 relative overflow-hidden">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-6 border-b border-graphite-800 gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-lg font-mono font-bold text-white tracking-wide">
              APPLICATION SECURITY DNA
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-neon">
              INTERACTIVE CONSTELLATION
            </span>
          </div>
          <p className="text-xs text-gray-400 font-mono mt-1">
            Structural topology mapping authentication boundaries, database sinks, and attack perimeters.
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono text-gray-400">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-red-glow inline-block" />
          <span>Critical Risk</span>
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500 ml-2 inline-block" />
          <span>High Risk</span>
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 ml-2 inline-block" />
          <span>Secure</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* Constellation Canvas (SVG) */}
        <div className="lg:col-span-8 bg-graphite-950/70 border border-graphite-800/80 rounded-xl p-4 flex items-center justify-center relative min-h-[460px]">
          {/* Subtle grid background */}
          <div className="absolute inset-0 opacity-15 pointer-events-none bg-[radial-gradient(#00f0ff_1px,transparent_1px)] [background-size:24px_24px]" />

          <svg viewBox="0 0 700 460" className="w-full h-full max-h-[440px]">
            {/* Edges */}
            {dna.edges.map((edge, idx) => {
              const srcNode = dna.nodes.find((n) => n.id === edge.source) || dna.nodes[0];
              const tgtNode = dna.nodes.find((n) => n.id === edge.target) || dna.nodes[0];
              const p1 = getNodeCoordinates(srcNode.category);
              const p2 = getNodeCoordinates(tgtNode.category);

              const isEdgeActive = selectedNodeId === srcNode.id || selectedNodeId === tgtNode.id;

              return (
                <g key={`edge-${idx}`}>
                  <line
                    x1={p1.x}
                    y1={p1.y}
                    x2={p2.x}
                    y2={p2.y}
                    stroke={isEdgeActive ? "#00F0FF" : "#222B3B"}
                    strokeWidth={isEdgeActive ? 2.5 : 1.5}
                    strokeDasharray={isEdgeActive ? "4 3" : undefined}
                    className={isEdgeActive ? "animate-pulse" : ""}
                  />
                  {/* Midpoint relation pill */}
                  <text
                    x={(p1.x + p2.x) / 2}
                    y={(p1.y + p2.y) / 2 - 6}
                    fill={isEdgeActive ? "#00F0FF" : "#64748B"}
                    fontSize="9"
                    fontFamily="monospace"
                    textAnchor="middle"
                  >
                    {edge.relation}
                  </text>
                </g>
              );
            })}

            {/* Nodes */}
            {dna.nodes.map((node) => {
              const coords = getNodeCoordinates(node.category);
              const isSelected = selectedNodeId === node.id;
              const hasCritical = node.risk_level === "CRITICAL";

              return (
                <g
                  key={node.id}
                  onClick={() => setSelectedNodeId(node.id)}
                  className="cursor-pointer group"
                >
                  {/* Outer pulsing ring for critical nodes */}
                  {hasCritical && (
                    <circle
                      cx={coords.x}
                      cy={coords.y}
                      r={isSelected ? 36 : 28}
                      className="fill-none stroke-rose-500/30 animate-ping"
                      strokeWidth={1}
                    />
                  )}

                  {/* Node Circle */}
                  <circle
                    cx={coords.x}
                    cy={coords.y}
                    r={isSelected ? 30 : 24}
                    className={`transition-all duration-200 ${
                      isSelected
                        ? "stroke-cyan-neon stroke-[3px] fill-graphite-900 shadow-cyan-glow"
                        : `${getRiskColor(node.risk_level)} stroke-2 hover:stroke-cyan-400`
                    }`}
                  />

                  {/* Node Label */}
                  <text
                    x={coords.x}
                    y={coords.y + 42}
                    fill={isSelected ? "#00F0FF" : "#E2E8F0"}
                    fontSize="11"
                    fontFamily="monospace"
                    fontWeight={isSelected ? "bold" : "normal"}
                    textAnchor="middle"
                  >
                    {node.name.length > 18 ? node.name.slice(0, 16) + "…" : node.name}
                  </text>

                  {/* Vulnerability Count badge if > 0 */}
                  {node.vulnerabilities_count > 0 && (
                    <g transform={`translate(${coords.x + 14}, ${coords.y - 18})`}>
                      <circle r="9" className="fill-rose-600 stroke-graphite-950 stroke-2" />
                      <text
                        x="0"
                        y="3"
                        fill="white"
                        fontSize="9"
                        fontFamily="monospace"
                        fontWeight="bold"
                        textAnchor="middle"
                      >
                        {node.vulnerabilities_count}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Node Details Card */}
        <div className="lg:col-span-4 bg-graphite-950/80 border border-graphite-700/80 rounded-xl p-5 font-mono">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-graphite-800">
            <div className="text-xs text-gray-400">NODE INSPECTOR</div>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                selectedNode.risk_level === "CRITICAL"
                  ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                  : selectedNode.risk_level === "HIGH"
                  ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                  : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
              }`}
            >
              {selectedNode.risk_level} RISK
            </span>
          </div>

          <h3 className="text-sm font-bold text-white mb-1">{selectedNode.name}</h3>
          <div className="text-xs text-cyan-neon mb-4">{selectedNode.technology}</div>

          <div className="space-y-3.5 text-xs">
            <div>
              <div className="text-gray-400 text-[11px] uppercase mb-1">Attack Surface Analysis</div>
              <p className="text-gray-300 leading-relaxed bg-graphite-900 p-2.5 rounded-lg border border-graphite-800">
                {selectedNode.attack_surface_desc}
              </p>
            </div>

            <div>
              <div className="text-gray-400 text-[11px] uppercase mb-1">
                Active Vulnerabilities ({selectedNode.vulnerabilities_count})
              </div>
              <div className="text-xs font-semibold text-rose-400">
                {selectedNode.vulnerabilities_count > 0
                  ? `${selectedNode.vulnerabilities_count} flaw(s) active on this perimeter.`
                  : "0 open vulnerabilities detected."}
              </div>
            </div>

            {selectedNode.files && selectedNode.files.length > 0 && (
              <div>
                <div className="text-gray-400 text-[11px] uppercase mb-1">Target Files Involved</div>
                <div className="space-y-1">
                  {selectedNode.files.map((f, i) => (
                    <div
                      key={i}
                      className="px-2 py-1 rounded bg-graphite-900 border border-graphite-800 text-[11px] text-gray-300 truncate"
                      title={f}
                    >
                      {f}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
