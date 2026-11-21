"use client";

import React, { useState } from "react";
import { askCopilot } from "@/lib/api";
import { CopilotResponse } from "@/lib/types";
import {
  Bot,
  Send,
  X,
  Sparkles,
  FileCode,
  ShieldAlert,
  ArrowRight,
  CheckCircle,
  HelpCircle,
  Loader2
} from "lucide-react";

interface SecurityCopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  projectId: string;
  scanId: string;
  isBeginnerMode: boolean;
  activeVulnerabilityId?: string;
}

interface Message {
  sender: "user" | "copilot";
  text: string;
  referencedFiles?: string[];
  recommendedActions?: string[];
}

export const SecurityCopilotDrawer: React.FC<SecurityCopilotDrawerProps> = ({
  isOpen,
  onClose,
  projectId,
  scanId,
  isBeginnerMode,
  activeVulnerabilityId
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: "copilot",
      text: "VULNEX AI Security Copilot initialized. I have full contextual telemetry on your active scan, AST data-flow traces, and attack perimeters. How can I assist your security review?",
      recommendedActions: [
        "Which vulnerability should I fix first?",
        "Show me the attack path.",
        "Did the latest patch introduce a regression?",
        "Explain this issue like I'm a beginner."
      ]
    }
  ]);
  const [inputText, setInputText] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  if (!isOpen) return null;

  const handleSend = async (questionToSend?: string) => {
    const q = (questionToSend || inputText).trim();
    if (!q || isLoading) return;

    setMessages((prev) => [...prev, { sender: "user", text: q }]);
    setInputText("");
    setIsLoading(true);

    try {
      const resp: CopilotResponse = await askCopilot({
        project_id: projectId,
        scan_id: scanId,
        question: q,
        current_vulnerability_id: activeVulnerabilityId,
        mode: isBeginnerMode ? "beginner" : "technical"
      });

      setMessages((prev) => [
        ...prev,
        {
          sender: "copilot",
          text: resp.answer,
          referencedFiles: resp.referenced_files,
          recommendedActions: resp.recommended_actions
        }
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          sender: "copilot",
          text: "VULNEX Security Engine: Response temporarily unavailable. Deterministic fallback telemetry is active in the main dashboard."
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full sm:w-[480px] bg-graphite-950 border-l border-violet-500/30 shadow-violet-glow z-50 flex flex-col font-mono">
      {/* Header */}
      <div className="p-4 border-b border-graphite-800 flex items-center justify-between bg-graphite-900/60">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-lg bg-violet-500/20 border border-violet-500/40 text-violet-neon">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="font-bold text-white text-sm">VULNEX COPILOT</h3>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-neon border border-violet-500/30">
                CONTEXT-AWARE
              </span>
            </div>
            <p className="text-[11px] text-gray-400">
              Mode: {isBeginnerMode ? "Beginner Friendly" : "Security Engineer"}
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

      {/* Message History */}
      <div className="p-4 overflow-y-auto space-y-4 flex-1 text-xs">
        {messages.map((m, idx) => {
          const isUser = m.sender === "user";

          return (
            <div
              key={idx}
              className={`flex flex-col ${isUser ? "items-end" : "items-start"}`}
            >
              <div
                className={`max-w-[90%] p-3.5 rounded-xl border leading-relaxed ${
                  isUser
                    ? "bg-cyan-500/15 border-cyan-500/40 text-cyan-100 shadow-cyan-glow"
                    : "bg-graphite-900 border-graphite-800 text-gray-200"
                }`}
              >
                <p className="whitespace-pre-wrap">{m.text}</p>

                {/* Referenced Code Files */}
                {m.referencedFiles && m.referencedFiles.length > 0 && (
                  <div className="mt-3 pt-2.5 border-t border-graphite-800 space-y-1">
                    <div className="text-[10px] uppercase text-gray-400 font-bold">
                      Referenced Code Context:
                    </div>
                    {m.referencedFiles.map((rf, i) => (
                      <div
                        key={i}
                        className="flex items-center space-x-1.5 text-[11px] text-cyan-neon"
                      >
                        <FileCode className="w-3.5 h-3.5" />
                        <span>{rf}</span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Recommended Actions / Suggested Questions */}
                {m.recommendedActions && m.recommendedActions.length > 0 && (
                  <div className="mt-3 pt-2.5 border-t border-graphite-800 space-y-1.5">
                    <div className="text-[10px] uppercase text-violet-neon font-bold">
                      Suggested Inquiries & Next Steps:
                    </div>
                    {m.recommendedActions.map((action, i) => (
                      <button
                        key={i}
                        onClick={() => handleSend(action)}
                        className="w-full text-left p-1.5 rounded bg-graphite-950 border border-graphite-800 hover:border-violet-500/50 text-[11px] text-gray-300 hover:text-white transition-all flex items-center justify-between group"
                      >
                        <span>{action}</span>
                        <ArrowRight className="w-3 h-3 text-gray-500 group-hover:text-violet-neon shrink-0 ml-1" />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {isLoading && (
          <div className="flex items-center space-x-2 text-xs text-gray-400 font-mono p-2">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-neon" />
            <span>VULNEX Copilot analyzing scan telemetry…</span>
          </div>
        )}
      </div>

      {/* Input bar */}
      <div className="p-3 border-t border-graphite-800 bg-graphite-900/80">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center space-x-2"
        >
          <input
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Ask about attack paths, confidence, fixes…"
            className="flex-1 bg-graphite-950 border border-graphite-700/80 focus:border-cyan-neon rounded-lg px-3 py-2 text-xs text-white placeholder-gray-500 focus:outline-none transition-all"
          />
          <button
            type="submit"
            disabled={isLoading || !inputText.trim()}
            className="p-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-graphite-950 disabled:opacity-40 transition-all shadow-cyan-glow"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};
