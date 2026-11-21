"use client";

import React from "react";
import {
  LayoutDashboard,
  Dna,
  GitBranch,
  ShieldAlert,
  Wrench,
  History,
  FlaskConical,
  Award,
  Bot,
  ExternalLink
} from "lucide-react";

export type TabType =
  | "overview"
  | "dna"
  | "attack-paths"
  | "vulnerabilities"
  | "fix-lab"
  | "timeline"
  | "research"
  | "passport";

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  openCriticalCount: number;
  unresolvedCount: number;
  regressionsCount: number;
  onOpenCopilot: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  openCriticalCount,
  unresolvedCount,
  regressionsCount,
  onOpenCopilot
}) => {
  const navItems = [
    { id: "overview" as TabType, label: "Overview", icon: LayoutDashboard },
    { id: "dna" as TabType, label: "Security DNA", icon: Dna, highlight: true },
    { id: "attack-paths" as TabType, label: "Attack Paths", icon: GitBranch },
    {
      id: "vulnerabilities" as TabType,
      label: "Vulnerabilities",
      icon: ShieldAlert,
      badge: unresolvedCount > 0 ? `${unresolvedCount}` : undefined,
      badgeColor: openCriticalCount > 0 ? "bg-rose-500 text-white" : "bg-cyan-500/20 text-cyan-neon"
    },
    { id: "fix-lab" as TabType, label: "AI Fix Lab", icon: Wrench, glow: true },
    {
      id: "timeline" as TabType,
      label: "Time Machine",
      icon: History,
      badge: regressionsCount > 0 ? `! Regress` : undefined,
      badgeColor: "bg-rose-600 text-white animate-pulse"
    },
    { id: "research" as TabType, label: "Research Lab", icon: FlaskConical },
    { id: "passport" as TabType, label: "Security Passport", icon: Award }
  ];

  return (
    <aside className="w-64 border-r border-graphite-700/80 bg-graphite-950 flex flex-col justify-between shrink-0 select-none">
      <div className="py-4">
        <div className="px-5 mb-3 text-[11px] font-mono uppercase tracking-wider text-gray-500">
          OPERATIONS LAB
        </div>

        <nav className="space-y-1 px-3">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-mono transition-all ${
                  isActive
                    ? "bg-cyan-500/15 border border-cyan-500/40 text-cyan-neon shadow-cyan-glow font-semibold"
                    : "text-gray-400 hover:text-white hover:bg-graphite-900 border border-transparent"
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon
                    className={`w-4 h-4 ${
                      isActive ? "text-cyan-neon" : "text-gray-400 group-hover:text-white"
                    }`}
                  />
                  <span>{item.label}</span>
                </div>

                {item.badge && (
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                      item.badgeColor || "bg-graphite-800 text-gray-300"
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Copilot Callout */}
      <div className="p-4 border-t border-graphite-800">
        <div className="p-3.5 rounded-xl border border-violet-500/30 bg-gradient-to-b from-violet-950/20 to-graphite-900 text-xs">
          <div className="flex items-center space-x-2 text-violet-neon font-mono font-semibold mb-1">
            <Bot className="w-4 h-4" />
            <span>AI Security Copilot</span>
          </div>
          <p className="text-[11px] text-gray-400 leading-relaxed mb-2.5">
            Grounded in your scanned code, AST data flow, and attack paths.
          </p>
          <button
            onClick={onOpenCopilot}
            className="w-full py-1.5 px-2.5 rounded-lg border border-violet-500/40 bg-violet-500/15 hover:bg-violet-500/25 text-violet-neon text-[11px] font-mono transition-all text-center font-medium"
          >
            Ask VULNEX
          </button>
        </div>
      </div>
    </aside>
  );
};
