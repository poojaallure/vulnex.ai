"use client";

import React from "react";
import { SecurityPassport } from "@/lib/types";
import {
  Award,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  QrCode,
  Download,
  Share2,
  Calendar,
  Lock,
  Cpu
} from "lucide-react";

interface SecurityPassportCardProps {
  passport: SecurityPassport;
}

export const SecurityPassportCard: React.FC<SecurityPassportCardProps> = ({ passport }) => {
  const isGradeA = passport.security_score >= 85;

  return (
    <div className="bg-graphite-900 border border-graphite-700/80 rounded-2xl p-6 font-mono relative overflow-hidden">
      {/* Background Cyberpunk Accents */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 left-0 w-64 h-64 bg-violet-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Passport Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-6 border-b border-graphite-800 gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-lg font-bold text-white tracking-wide">
              VULNEX SECURITY PASSPORT
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-neon font-bold">
              OFFICIAL VERIFICATION
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Certified application security certificate with independent re-scan verification proof.
          </p>
        </div>

        <button
          onClick={() => window.print()}
          className="flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-graphite-700 hover:border-cyan-neon bg-graphite-950 text-xs text-gray-300 hover:text-white transition-all self-start sm:self-auto"
        >
          <Download className="w-3.5 h-3.5 text-cyan-neon" />
          <span>EXPORT CERTIFICATE</span>
        </button>
      </div>

      {/* Main Passport Certificate Layout */}
      <div className="bg-gradient-to-br from-graphite-950 to-graphite-900 border-2 border-cyan-500/30 rounded-2xl p-6 shadow-cyan-glow relative overflow-hidden">
        {/* Certificate Watermark Banner */}
        <div className="flex items-center justify-between border-b border-graphite-800 pb-4 mb-6">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500/30 to-violet-500/30 border border-cyan-neon flex items-center justify-center">
              <Award className="w-6 h-6 text-cyan-neon" />
            </div>
            <div>
              <div className="text-xs text-gray-400">APPLICATION PASSPORT</div>
              <div className="text-base font-bold text-white tracking-wide">
                {passport.project_name}
              </div>
            </div>
          </div>

          <div className="text-right">
            <div className="text-xs text-gray-400">PASSPORT ID</div>
            <div className="text-xs text-cyan-neon font-bold">
              {passport.project_id.toUpperCase()}
            </div>
          </div>
        </div>

        {/* Central Metric Badges */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="p-4 rounded-xl border border-graphite-800 bg-graphite-950/70 text-center">
            <div className="text-[11px] text-gray-400 uppercase mb-1">Security Score</div>
            <div
              className={`text-3xl font-black ${
                passport.security_score >= 80
                  ? "text-emerald-400"
                  : passport.security_score >= 60
                  ? "text-amber-400"
                  : "text-rose-400"
              }`}
            >
              {passport.security_score}
              <span className="text-sm font-normal text-gray-500">/100</span>
            </div>
          </div>

          <div className="p-4 rounded-xl border border-graphite-800 bg-graphite-950/70 text-center">
            <div className="text-[11px] text-gray-400 uppercase mb-1">Risk Evaluation</div>
            <div
              className={`text-xl font-bold mt-1.5 ${
                passport.risk_level === "LOW"
                  ? "text-emerald-400"
                  : passport.risk_level === "MEDIUM"
                  ? "text-cyan-400"
                  : "text-rose-400"
              }`}
            >
              {passport.risk_level}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-graphite-800 bg-graphite-950/70 text-center">
            <div className="text-[11px] text-gray-400 uppercase mb-1">Verified Fixes</div>
            <div className="text-3xl font-black text-cyan-neon mt-0.5">
              {passport.verified_fixes_count}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-graphite-800 bg-graphite-950/70 text-center">
            <div className="text-[11px] text-gray-400 uppercase mb-1">Open Critical</div>
            <div
              className={`text-3xl font-black mt-0.5 ${
                passport.open_critical_count === 0 ? "text-emerald-400" : "text-rose-400"
              }`}
            >
              {passport.open_critical_count}
            </div>
          </div>
        </div>

        {/* Detailed Verification Matrix */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs mb-6">
          <div className="flex items-center justify-between p-3 rounded-lg bg-graphite-950 border border-graphite-800">
            <span className="text-gray-400">Dependency Supply Chain Health:</span>
            <span className="font-bold text-white">{passport.dependency_health_pct}%</span>
          </div>

          <div className="flex items-center justify-between p-3 rounded-lg bg-graphite-950 border border-graphite-800">
            <span className="text-gray-400">Secret & Credential Health:</span>
            <span className="font-bold text-white">{passport.secret_health_pct}%</span>
          </div>

          <div className="flex items-center justify-between p-3 rounded-lg bg-graphite-950 border border-graphite-800">
            <span className="text-gray-400">Attack Surface Classification:</span>
            <span className="font-bold text-cyan-neon">{passport.attack_surface_rating}</span>
          </div>

          <div className="flex items-center justify-between p-3 rounded-lg bg-graphite-950 border border-graphite-800">
            <span className="text-gray-400">Verification Percentage:</span>
            <span className="font-bold text-emerald-400">{passport.verification_pct}% VERIFIED</span>
          </div>
        </div>

        {/* Certificate Seal & Timestamp */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pt-4 border-t border-graphite-800 text-[11px] text-gray-400 gap-2">
          <div className="flex items-center space-x-2">
            <Calendar className="w-3.5 h-3.5 text-violet-neon" />
            <span>Timestamp: {passport.last_verified}</span>
          </div>
          <div className="text-cyan-neon font-semibold">
            PROVEN BY VULNEX INDEPENDENT VERIFICATION ENGINE
          </div>
        </div>
      </div>
    </div>
  );
};
