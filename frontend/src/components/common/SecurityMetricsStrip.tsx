import { useQuery } from "@tanstack/react-query";
import { api } from "../../services/api";
import type { DashboardData } from "../../types";
import { Target, ShieldAlert, ShieldCheck, Layers } from "lucide-react";

interface SecurityMetricsStripProps {
  variant?: "full" | "compact";
  className?: string;
}

export default function SecurityMetricsStrip({ variant = "full", className = "" }: SecurityMetricsStripProps) {
  const { data } = useQuery<DashboardData>({
    queryKey: ["dashboard"],
    queryFn: api.getDashboard,
    refetchInterval: 5000
  });

  const stats = data?.stats ?? {
    total_missions: 0,
    assets_scanned: 0,
    total_findings: 0,
    critical_findings: 0,
    high_findings: 0,
    security_score: 100,
    features_identified: 0
  };

  const securityScore = stats.security_score ?? (stats.total_findings === 0 ? 100 : Math.max(30, 100 - stats.total_findings * 12));
  const scoreColor = securityScore >= 80 ? "text-[#10B981]" : securityScore >= 60 ? "text-[#F59E0B]" : "text-[#EF4444]";
  const scoreBadge = securityScore >= 80 ? "Hardened" : securityScore >= 60 ? "Moderate" : "Elevated Risk";

  if (variant === "compact") {
    return (
      <div className={`grid grid-cols-2 lg:grid-cols-4 gap-4 ${className}`}>
        <div className="bg-[#141A23] border-2 border-black shadow-[3px_3px_0px_#000] p-4 rounded-xl flex items-center justify-between hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_#000] transition-all duration-150">
          <div>
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-wider block font-mono">Target Assets</span>
            <p className="text-xl font-black text-[#F8FAFC] mt-1">{stats.assets_scanned || stats.total_missions}</p>
          </div>
          <div className="p-2.5 bg-[#0D1117] rounded-lg text-[#38BDF8] border-2 border-black shadow-[1.5px_1.5px_0px_#000]">
            <Target className="w-4 h-4" />
          </div>
        </div>
        <div className="bg-[#141A23] border-2 border-black shadow-[3px_3px_0px_#000] p-4 rounded-xl flex items-center justify-between hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_#000] transition-all duration-150">
          <div>
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-wider block font-mono">Active Findings</span>
            <p className="text-xl font-black text-[#EF4444] mt-1">{stats.total_findings}</p>
          </div>
          <div className="p-2.5 bg-[#0D1117] rounded-lg text-[#EF4444] border-2 border-black shadow-[1.5px_1.5px_0px_#000]">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>
        <div className="bg-[#141A23] border-2 border-black shadow-[3px_3px_0px_#000] p-4 rounded-xl flex items-center justify-between hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_#000] transition-all duration-150">
          <div>
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-wider block font-mono">Defense Posture</span>
            <p className={`text-xl font-black mt-1 ${scoreColor}`}>{securityScore} <span className="text-xs text-[#64748B]">/ 100</span></p>
          </div>
          <div className="p-2.5 bg-[#0D1117] rounded-lg text-[#10B981] border-2 border-black shadow-[1.5px_1.5px_0px_#000]">
            <ShieldCheck className="w-4 h-4" />
          </div>
        </div>
        <div className="bg-[#141A23] border-2 border-black shadow-[3px_3px_0px_#000] p-4 rounded-xl flex items-center justify-between hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_#000] transition-all duration-150">
          <div>
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-wider block font-mono">Capabilities</span>
            <p className="text-xl font-black text-[#E2F952] mt-1">{stats.features_identified}</p>
          </div>
          <div className="p-2.5 bg-[#0D1117] rounded-lg text-[#E2F952] border-2 border-black shadow-[1.5px_1.5px_0px_#000]">
            <Layers className="w-4 h-4" />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 ${className}`}>
      {/* Target Assets Scanned */}
      <div className="bg-[#141A23] border-2 border-black shadow-[3px_3px_0px_#000] p-5 rounded-xl flex flex-col justify-between min-h-[136px] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_#000] transition-all duration-150">
        <div className="flex justify-between items-start">
          <div>
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-wider block font-mono">Target Assets</span>
            <div className="text-3xl font-black text-[#F8FAFC] tracking-tight mt-1.5">{stats.assets_scanned || stats.total_missions}</div>
          </div>
          <div className="p-2.5 bg-[#0D1117] rounded-lg text-[#38BDF8] border-2 border-black shadow-[1.5px_1.5px_0px_#000] flex items-center justify-center shrink-0">
            <Target className="w-5 h-5" />
          </div>
        </div>
        <div className="mt-4 pt-3 border-t border-[#202938] flex items-center gap-1.5 text-xs text-[#94A3B8]">
          <span className="text-[#38BDF8] font-bold font-mono">{stats.total_missions}</span>
          <span className="font-editorial italic">missions evaluated</span>
        </div>
      </div>

      {/* Security Findings */}
      <div className="bg-[#141A23] border-2 border-black shadow-[3px_3px_0px_#000] p-5 rounded-xl flex flex-col justify-between min-h-[136px] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_#000] transition-all duration-150">
        <div className="flex justify-between items-start">
          <div>
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-wider block font-mono">Active Findings</span>
            <div className="text-3xl font-black text-[#EF4444] tracking-tight mt-1.5">{stats.total_findings}</div>
          </div>
          <div className="p-2.5 bg-[#0D1117] rounded-lg text-[#EF4444] border-2 border-black shadow-[1.5px_1.5px_0px_#000] flex items-center justify-center shrink-0">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>
        <div className="mt-4 pt-3 border-t border-[#202938] flex items-center gap-1.5 text-xs">
          <span className="px-1.5 py-0.5 rounded bg-[#EF4444] text-black border border-black font-black font-mono text-[10px] shadow-[1px_1px_0px_#000]">
            {stats.high_findings || 0} High / Critical
          </span>
          <span className="text-[#94A3B8] font-editorial italic">requiring attention</span>
        </div>
      </div>

      {/* Defense Posture Score */}
      <div className="bg-[#141A23] border-2 border-black shadow-[3px_3px_0px_#000] p-5 rounded-xl flex flex-col justify-between min-h-[136px] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_#000] transition-all duration-150">
        <div className="flex justify-between items-start">
          <div>
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-wider block font-mono">Defense Posture</span>
            <div className="flex items-baseline gap-1.5 mt-1.5">
              <span className={`text-3xl font-black tracking-tight ${scoreColor}`}>{securityScore}</span>
              <span className="text-xs font-semibold text-[#64748B]">/ 100</span>
            </div>
          </div>
          <div className="p-2.5 bg-[#0D1117] rounded-lg text-[#10B981] border-2 border-black shadow-[1.5px_1.5px_0px_#000] flex items-center justify-center shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>
        <div className="mt-4 pt-3 border-t border-[#202938] flex items-center gap-1.5 text-xs">
          <span className="px-2 py-0.5 rounded border border-black bg-[#E2F952] text-black text-[10px] font-black font-mono shadow-[1px_1px_0px_#000]">
            {scoreBadge}
          </span>
          <span className="text-[#94A3B8] font-editorial italic">resilience rating</span>
        </div>
      </div>

      {/* Capabilities Mapped */}
      <div className="bg-[#141A23] border-2 border-black shadow-[3px_3px_0px_#000] p-5 rounded-xl flex flex-col justify-between min-h-[136px] hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_#000] transition-all duration-150">
        <div className="flex justify-between items-start">
          <div>
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-wider block font-mono">Surface Capabilities</span>
            <div className="text-3xl font-black text-[#F8FAFC] tracking-tight mt-1.5">{stats.features_identified}</div>
          </div>
          <div className="p-2.5 bg-[#0D1117] rounded-lg text-[#E2F952] border-2 border-black shadow-[1.5px_1.5px_0px_#000] flex items-center justify-center shrink-0">
            <Layers className="w-5 h-5" />
          </div>
        </div>
        <div className="mt-4 pt-3 border-t border-[#202938] flex items-center gap-1.5 text-xs text-[#94A3B8]">
          <span className="text-[#E2F952] font-bold font-mono">{stats.features_identified}</span>
          <span className="font-editorial italic">functional areas mapped</span>
        </div>
      </div>
    </div>
  );
}
