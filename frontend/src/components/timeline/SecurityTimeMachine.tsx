"use client";

import React from "react";
import { TimelineEvent } from "@/lib/types";
import {
  History,
  TrendingUp,
  TrendingDown,
  AlertOctagon,
  CheckCircle2,
  Calendar,
  AlertTriangle,
  ArrowUpRight,
  ShieldAlert
} from "lucide-react";

interface SecurityTimeMachineProps {
  timeline: TimelineEvent[];
  activeRegressions: string[];
}

export const SecurityTimeMachine: React.FC<SecurityTimeMachineProps> = ({
  timeline,
  activeRegressions
}) => {
  return (
    <div className="bg-graphite-900 border border-graphite-700/80 rounded-2xl p-6 font-mono relative overflow-hidden">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-6 border-b border-graphite-800 gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-lg font-bold text-white tracking-wide">
              SECURITY TIME MACHINE
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/30 text-violet-neon font-bold">
              HISTORICAL TELEMETRY
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Tracks evolution of security posture across iterations, commits, and autonomous repairs.
          </p>
        </div>

        <div className="text-xs text-cyan-neon font-semibold">
          {timeline.length} Recorded Cycles
        </div>
      </div>

      {/* Prominent Security Regression Radar Alert if Regressions exist */}
      {activeRegressions.length > 0 && (
        <div className="mb-6 p-4 rounded-xl border border-rose-500 bg-rose-950/40 shadow-red-glow animate-pulse">
          <div className="flex items-center space-x-2 text-rose-400 font-bold text-sm mb-2">
            <AlertOctagon className="w-5 h-5 text-rose-500" />
            <span>⚠ SECURITY REGRESSION RADAR ALERT</span>
          </div>
          <div className="space-y-1.5 text-xs text-rose-200">
            {activeRegressions.map((reg, idx) => (
              <div key={idx} className="flex items-start space-x-2">
                <span className="text-rose-400 font-bold">•</span>
                <span>{reg}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Timeline Iteration Track */}
      <div className="relative pl-6 space-y-8 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-[2px] before:bg-gradient-to-b before:from-cyan-500 before:via-violet-500 before:to-emerald-500">
        {timeline.map((event, idx) => {
          const isLatest = idx === timeline.length - 1;
          const isPositive = event.score_delta > 0;

          return (
            <div key={event.scan_id || idx} className="relative group">
              {/* Dot */}
              <div
                className={`absolute -left-[29px] top-1.5 w-4 h-4 rounded-full border-2 bg-graphite-950 transition-all ${
                  isLatest
                    ? "border-cyan-neon shadow-cyan-glow scale-125"
                    : "border-gray-500 group-hover:border-cyan-400"
                }`}
              />

              <div
                className={`p-4 rounded-xl border transition-all ${
                  isLatest
                    ? "bg-graphite-950/90 border-cyan-500/40 shadow-cyan-glow"
                    : "bg-graphite-950/60 border-graphite-800"
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 mb-2 border-b border-graphite-800/80 gap-2 text-xs">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-cyan-neon">{event.version}</span>
                    <span className="text-gray-500">•</span>
                    <span className="text-gray-400 flex items-center space-x-1">
                      <Calendar className="w-3 h-3 text-gray-500" />
                      <span>{event.timestamp}</span>
                    </span>
                  </div>

                  {/* Score Pill */}
                  <div className="flex items-center space-x-2 self-start sm:self-auto">
                    <span className="text-gray-400">Score:</span>
                    <span className="text-sm font-bold text-white">{event.score}/100</span>
                    {event.score_delta !== 0 && (
                      <span
                        className={`text-[11px] font-bold px-1.5 py-0.5 rounded flex items-center ${
                          isPositive
                            ? "bg-emerald-500/20 text-emerald-300"
                            : "bg-rose-500/20 text-rose-300"
                        }`}
                      >
                        {isPositive ? `+${event.score_delta}` : `${event.score_delta}`}
                      </span>
                    )}
                  </div>
                </div>

                <p className="text-xs text-gray-300 leading-relaxed mb-3">{event.summary}</p>

                {/* Sub-metrics */}
                <div className="flex flex-wrap items-center gap-3 text-[11px]">
                  <span className="text-gray-400">
                    New Findings:{" "}
                    <span className="text-white font-bold">{event.new_vulnerabilities_count}</span>
                  </span>
                  <span className="text-gray-400">
                    Verified Fixes:{" "}
                    <span className="text-emerald-400 font-bold">{event.fixed_vulnerabilities_count}</span>
                  </span>
                  {event.regressions && event.regressions.length > 0 && (
                    <span className="text-rose-400 font-bold">
                      ⚠ {event.regressions.length} Regression(s)
                    </span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
