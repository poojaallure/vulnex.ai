"use client";

import React from "react";
import { SecurityRadarMetrics } from "@/lib/types";

interface SecurityRadarChartProps {
  metrics: SecurityRadarMetrics;
}

export const SecurityRadarChart: React.FC<SecurityRadarChartProps> = ({ metrics }) => {
  const axes = [
    { key: "authentication", label: "Authentication", value: metrics.authentication },
    { key: "authorization", label: "Authorization", value: metrics.authorization },
    { key: "secrets", label: "Secrets", value: metrics.secrets },
    { key: "dependencies", label: "Dependencies", value: metrics.dependencies },
    { key: "input_validation", label: "Input Validation", value: metrics.input_validation },
    { key: "api_security", label: "API Security", value: metrics.api_security },
    { key: "configuration", label: "Config", value: metrics.configuration },
    { key: "data_protection", label: "Data Protection", value: metrics.data_protection },
    { key: "code_safety", label: "Code Safety", value: metrics.code_safety },
    { key: "ai_confidence", label: "AI Confidence", value: metrics.ai_confidence },
  ];

  const totalAxes = axes.length;
  const radius = 110;
  const cx = 150;
  const cy = 150;

  const getCoordinates = (index: number, val: number) => {
    const angle = (Math.PI * 2 / totalAxes) * index - Math.PI / 2;
    const r = (val / 100) * radius;
    return {
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
    };
  };

  const polygonPoints = axes
    .map((axis, i) => {
      const { x, y } = getCoordinates(i, axis.value);
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <div className="bg-graphite-900 border border-graphite-700/80 rounded-2xl p-6 font-mono flex flex-col items-center">
      <div className="w-full flex items-center justify-between pb-3 mb-4 border-b border-graphite-800">
        <h3 className="text-sm font-bold text-white tracking-wide">SECURITY RADAR</h3>
        <span className="text-[10px] text-cyan-neon font-bold px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30">
          10-AXIS DEFENSE
        </span>
      </div>

      <div className="relative w-[300px] h-[300px]">
        <svg viewBox="0 0 300 300" className="w-full h-full">
          {/* Background concentric polygons */}
          {[0.25, 0.5, 0.75, 1.0].map((level, idx) => {
            const points = axes
              .map((_, i) => {
                const angle = (Math.PI * 2 / totalAxes) * i - Math.PI / 2;
                const r = level * radius;
                return `${cx + r * Math.cos(angle)},${cy + r * Math.sin(angle)}`;
              })
              .join(" ");
            return (
              <polygon
                key={idx}
                points={points}
                fill="none"
                stroke="#1E293B"
                strokeWidth={1}
                strokeDasharray={idx < 3 ? "2 2" : undefined}
              />
            );
          })}

          {/* Radial axis lines */}
          {axes.map((_, i) => {
            const { x, y } = getCoordinates(i, 100);
            return (
              <line
                key={i}
                x1={cx}
                y1={cy}
                x2={x}
                y2={y}
                stroke="#222B3B"
                strokeWidth={1}
              />
            );
          })}

          {/* Data Polygon */}
          <polygon
            points={polygonPoints}
            fill="rgba(0, 240, 255, 0.22)"
            stroke="#00F0FF"
            strokeWidth={2}
            className="filter drop-shadow-[0_0_8px_rgba(0,240,255,0.4)]"
          />

          {/* Axis labels & dots */}
          {axes.map((axis, i) => {
            const { x, y } = getCoordinates(i, axis.value);
            const labelCoord = getCoordinates(i, 118);
            const isWeak = axis.value < 60;

            return (
              <g key={axis.key}>
                <circle
                  cx={x}
                  cy={y}
                  r={3.5}
                  className={isWeak ? "fill-rose-500" : "fill-cyan-neon"}
                />
                <text
                  x={labelCoord.x}
                  y={labelCoord.y}
                  fill={isWeak ? "#F43F5E" : "#94A3B8"}
                  fontSize="8"
                  textAnchor="middle"
                  alignmentBaseline="middle"
                  fontWeight={isWeak ? "bold" : "normal"}
                >
                  {axis.label} ({axis.value})
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Axis value breakdown */}
      <div className="w-full grid grid-cols-2 gap-x-4 gap-y-1.5 mt-4 pt-3 border-t border-graphite-800 text-[11px]">
        {axes.map((a) => (
          <div key={a.key} className="flex justify-between items-center text-gray-300">
            <span className="truncate text-gray-400">{a.label}</span>
            <span className={`font-bold ${a.value < 60 ? "text-rose-400" : "text-cyan-neon"}`}>
              {a.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
