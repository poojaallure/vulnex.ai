"use client";

import React from "react";
import { ShieldCheck, Cpu, Play, Upload, Sparkles, Terminal, Activity, ToggleLeft, ToggleRight } from "lucide-react";

interface TopbarProps {
  projectName: string;
  isBeginnerMode: boolean;
  setIsBeginnerMode: (val: boolean) => void;
  onOpenUpload: () => void;
  onRunDemo: () => void;
  onOpenCopilot: () => void;
  isScanning: boolean;
}

export const Topbar: React.FC<TopbarProps> = ({
  projectName,
  isBeginnerMode,
  setIsBeginnerMode,
  onOpenUpload,
  onRunDemo,
  onOpenCopilot,
  isScanning,
}) => {
  return (
    <header className="h-16 border-b border-graphite-700/80 bg-graphite-950/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Brand & Tagline */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2.5">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-neon/20 to-violet-neon/20 border border-cyan-500/40 flex items-center justify-center shadow-cyan-glow">
            <ShieldCheck className="w-5 h-5 text-cyan-neon" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-mono font-bold tracking-wider text-base text-white">VULNEX AI</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded border border-cyan-500/30 bg-cyan-500/10 text-cyan-neon font-mono">
                SOC v1.0
              </span>
            </div>
            <div className="text-[11px] text-gray-400 font-mono tracking-tight hidden sm:block">
              AI BUILDS. <span className="text-cyan-neon font-semibold">VULNEX VERIFIES.</span>
            </div>
          </div>
        </div>

        {/* Active Project Badge */}
        <div className="hidden lg:flex items-center space-x-2 px-3 py-1 rounded-md bg-graphite-900 border border-graphite-700/80 text-xs">
          <Terminal className="w-3.5 h-3.5 text-violet-neon" />
          <span className="text-gray-400">Target:</span>
          <span className="text-white font-medium font-mono">{projectName}</span>
        </div>
      </div>

      {/* Center / Right controls */}
      <div className="flex items-center space-x-3">
        {/* Beginner vs Security Engineer Mode Toggle */}
        <button
          onClick={() => setIsBeginnerMode(!isBeginnerMode)}
          className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all ${
            isBeginnerMode
              ? "bg-amber-500/10 border-amber-500/40 text-amber-400"
              : "bg-cyan-500/10 border-cyan-500/40 text-cyan-neon shadow-cyan-glow"
          }`}
          title="Toggle interface mode between simplified explanations and technical CWE details"
        >
          {isBeginnerMode ? <ToggleLeft className="w-4 h-4" /> : <ToggleRight className="w-4 h-4" />}
          <span className="hidden md:inline font-semibold">
            {isBeginnerMode ? "BEGINNER MODE" : "SECURITY ENGINEER MODE"}
          </span>
        </button>

        {/* Quick Demo Run Button */}
        <button
          onClick={onRunDemo}
          disabled={isScanning}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-violet-500/40 bg-violet-500/10 hover:bg-violet-500/20 text-violet-neon text-xs font-mono transition-all shadow-violet-glow disabled:opacity-50"
        >
          <Play className="w-3.5 h-3.5 fill-violet-neon" />
          <span>LOAD DEMO APP</span>
        </button>

        {/* Upload Archive Button */}
        <button
          onClick={onOpenUpload}
          disabled={isScanning}
          className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-400 hover:to-cyan-500 text-graphite-950 text-xs font-bold font-mono tracking-wide transition-all shadow-cyan-glow disabled:opacity-50"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>SCAN ZIP</span>
        </button>

        {/* AI Copilot Trigger */}
        <button
          onClick={onOpenCopilot}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-graphite-900 hover:border-cyan-neon text-cyan-neon text-xs font-mono transition-all"
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Ask Copilot</span>
        </button>
      </div>
    </header>
  );
};
