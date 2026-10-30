import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../services/api";
import type { MissionDetail as MissionDetailType, TimelineTask } from "../types";
import SecurityMetricsStrip from "../components/common/SecurityMetricsStrip";
import {
  Clock,
  Calendar,
  Layers,
  Compass,
  FileText,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  ShieldCheck,
  ArrowLeft,
  ChevronRight,
  Sparkles
} from "lucide-react";

const getOwaspCategory = (category?: string): { code: string; name: string } => {
  switch (category?.toLowerCase()) {
    case "missing_csrf":
    case "admin_surface":
    case "exposed_endpoint":
      return { code: "A01:2025", name: "Broken Access Control" };
    case "missing_security_headers":
    case "verbose_error_leak":
      return { code: "A02:2025", name: "Security Misconfiguration" };
    case "vulnerable_dependency":
      return { code: "A03:2025", name: "Software Supply Chain Failures" };
    case "sensitive_input":
      return { code: "A05:2025", name: "Injection" };
    case "weak_authentication":
      return { code: "A07:2025", name: "Authentication Failures" };
    case "missing_subresource_integrity":
    case "file_upload_risk":
      return { code: "A08:2025", name: "Software or Data Integrity Failures" };
    default:
      return { code: "A02:2025", name: "Security Misconfiguration" };
  }
};

const getTaskLabel = (task: string): string => {
  switch (task) {
    case "RUN_RECON":
      return "RECON AGENT";
    case "EXTRACT_FEATURES":
      return "FEATURE EXTRACTION AGENT";
    case "RUN_EFFICIENT_FETCH":
      return "EFFICIENT FETCH WORKER";
    case "RUN_ANALYSIS":
      return "ANALYSIS AGENT (LLM)";
    case "RUN_SEVERITY_MODEL":
      return "SEVERITY MODEL (ML)";
    case "GENERATE_REPORT":
      return "REPORT AGENT";
    default:
      return task;
  }
};

const getCapabilityLabel = (name: string): string => {
  switch (name.toLowerCase()) {
    case "unknown":
      return "General Web Surface";
    case "api":
      return "API Gateway";
    default:
      return name.replace("_", " ").replace(/\b\w/g, l => l.toUpperCase());
  }
};

const getCapabilityFindings = (featureName: string, findings: any[]) => {
  const norm = featureName.toLowerCase();
  return findings.filter(f => {
    const cat = (f.category || "").toLowerCase();
    if (norm === "security_headers" && cat === "missing_security_headers") return true;
    if (norm === "authentication" && (cat === "weak_authentication" || cat === "missing_csrf")) return true;
    if (norm === "admin_panel" && cat === "admin_surface") return true;
    if (norm === "file_upload" && cat === "file_upload_risk") return true;
    if (norm === "api" && cat === "exposed_endpoint") return true;
    if (norm === "dashboard") return false;
    return false;
  });
};

export default function MissionDetail() {
  const { id } = useParams<{ id: string }>();
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  const { data: mission, isLoading, error } = useQuery<MissionDetailType>({
    queryKey: ["mission", id],
    queryFn: () => api.getMissionDetail(id!),
    enabled: !!id,
    refetchInterval: 5000
  });

  const { data: timeline } = useQuery<TimelineTask[]>({
    queryKey: ["timeline", id],
    queryFn: () => api.getMissionTimeline(id!),
    enabled: !!id,
    refetchInterval: 5000
  });

  const toggleFinding = (fId: string) => {
    setExpandedFindings(prev => ({ ...prev, [fId]: !prev[fId] }));
  };

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-[#090D16] min-h-[500px]">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 rounded-full border-2 border-t-transparent border-[#38BDF8] animate-spin"></div>
          <span className="text-[#64748B] text-xs font-mono tracking-wider uppercase">Loading Mission Telemetry...</span>
        </div>
      </div>
    );
  }

  if (error || !mission) {
    return (
      <div className="bg-[#0F172A] border border-[#1E293B] p-8 rounded-xl text-center max-w-xl mx-auto mt-12 space-y-4">
        <ShieldAlert className="w-12 h-12 text-[#EF4444] mx-auto animate-bounce" />
        <h3 className="text-base font-bold text-[#F8FAFC]">Mission Loading Failed</h3>
        <p className="text-xs text-[#64748B]">The requested mission ({id}) could not be retrieved from the database.</p>
        <Link to="/" className="inline-flex items-center gap-2 text-xs font-bold text-[#38BDF8] hover:underline mt-4">
          <ArrowLeft className="w-4 h-4" /> Back to Command Center
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header navigation bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b-2 border-black pb-5">
        <div className="flex items-center gap-3">
          <Link to="/" className="p-2.5 bg-[#141A23] border-2 border-black rounded shadow-[2px_2px_0px_#000000] hover:bg-[#1E293B] text-[#94A3B8] hover:text-[#F8FAFC] transition-transform active:translate-x-0.5 active:translate-y-0.5">
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2 text-[11px] text-[#64748B]">
              <Link to="/" className="hover:underline">Missions</Link>
              <ChevronRight className="w-3 h-3" />
              <span className="font-mono text-[#E2F952]">{mission.mission_id}</span>
            </div>
            <h1 className="text-xl font-bold text-[#F8FAFC] mt-0.5 tracking-tight">
              <span>Mission </span>
              <span className="font-editorial italic font-normal text-[#E2F952]">Inspection Window</span>
            </h1>
          </div>
        </div>

        {mission.report_id && (
          <Link
            to={`/reports?id=${mission.report_id}`}
            className="px-4 py-2 bg-[#E2F952] text-black font-extrabold text-xs rounded border-2 border-black shadow-[3px_3px_0px_#000000] hover:shadow-[1px_1px_0px_#000000] hover:translate-x-[2px] hover:translate-y-[2px] transition-all flex items-center gap-1.5"
          >
            <FileText className="w-4 h-4" /> Read Security Report
          </Link>
        )}
      </div>

      {/* Common Global Telemetry Strip */}
      <SecurityMetricsStrip variant="full" />

      {/* Section 1 — Mission Summary */}
      <div className="bg-[#141A23] border-2 border-black p-5 rounded shadow-[4px_4px_0px_#000000] grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <div>
          <p className="text-[10px] font-bold text-[#64748B] uppercase tracking-wider">Mission ID</p>
          <p className="text-sm font-mono font-bold text-[#E2F952] mt-1">{mission.mission_id}</p>
        </div>
        <div>
          <p className="text-[10px] font-bold text-[#64748B] uppercase tracking-wider">Target Domain</p>
          <a
            href={mission.target_url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm font-medium text-[#F8FAFC] hover:text-[#E2F952] hover:underline mt-1 truncate max-w-xs block font-mono"
            title={mission.target_url}
          >
            {mission.target_url || "https://example.com"}
          </a>
        </div>
        <div>
          <p className="text-[10px] font-bold text-[#64748B] uppercase tracking-wider">Execution Status</p>
          <div className="mt-1">
            <span className={`px-2.5 py-0.5 rounded text-[10px] font-black uppercase tracking-wider border-2 border-black shadow-[2px_2px_0px_#000000] ${
              mission.status === "completed" ? "bg-[#10B981] text-black" :
              mission.status === "failed" ? "bg-[#EF4444] text-white" :
              "bg-[#F59E0B] text-black animate-pulse"
            }`}>
              {mission.status}
            </span>
          </div>
        </div>
        <div>
          <p className="text-[10px] font-bold text-[#64748B] uppercase tracking-wider">Total Runtime</p>
          <p className="text-sm font-semibold text-[#F8FAFC] mt-1 flex items-center gap-1.5 font-mono">
            <Clock className="w-3.5 h-3.5 text-[#E2F952]" /> {mission.runtime}
          </p>
        </div>
        <div>
          <p className="text-[10px] font-bold text-[#64748B] uppercase tracking-wider">Generated At</p>
          <p className="text-sm font-medium text-[#94A3B8] mt-1 flex items-center gap-1.5 font-mono text-xs">
            <Calendar className="w-3.5 h-3.5 text-[#64748B]" /> {mission.generated_at ? new Date(mission.generated_at).toLocaleString() : "Unknown"}
          </p>
        </div>
      </div>

      {/* Grid: Recon and Features */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Section 2 — Recon Discovery Summary */}
        <div className="bg-[#141A23] border-2 border-black p-5 rounded shadow-[4px_4px_0px_#000000] xl:col-span-2 space-y-5">
          <h3 className="text-sm font-bold text-[#F8FAFC] border-b-2 border-black pb-3 flex items-center gap-2">
            <Compass className="w-4 h-4 text-[#E2F952]" /> <span>Recon </span><span className="font-editorial italic font-normal text-[#E2F952]">Discovery Summary</span>
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
            <div className="bg-[#0E1217] border-2 border-black p-3.5 rounded shadow-[2px_2px_0px_#000000]">
              <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider">Routes</span>
              <p className="text-xl font-bold font-mono text-[#F8FAFC] mt-1">{mission.recon_summary.routes}</p>
            </div>
            <div className="bg-[#0E1217] border-2 border-black p-3.5 rounded shadow-[2px_2px_0px_#000000]">
              <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider">Forms</span>
              <p className="text-xl font-bold font-mono text-[#F8FAFC] mt-1">{mission.recon_summary.forms}</p>
            </div>
            <div className="bg-[#0E1217] border-2 border-black p-3.5 rounded shadow-[2px_2px_0px_#000000]">
              <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider">Inputs</span>
              <p className="text-xl font-bold font-mono text-[#F8FAFC] mt-1">{mission.recon_summary.inputs}</p>
            </div>
            <div className="bg-[#0E1217] border-2 border-black p-3.5 rounded shadow-[2px_2px_0px_#000000]">
              <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider">Buttons</span>
              <p className="text-xl font-bold font-mono text-[#F8FAFC] mt-1">{mission.recon_summary.buttons}</p>
            </div>
            <div className="bg-[#0E1217] border-2 border-black p-3.5 rounded shadow-[2px_2px_0px_#000000]">
              <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider">Scripts</span>
              <p className="text-xl font-bold font-mono text-[#F8FAFC] mt-1">{mission.recon_summary.scripts}</p>
            </div>
            <div className="bg-[#0E1217] border-2 border-black p-3.5 rounded shadow-[2px_2px_0px_#000000]">
              <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider">Links</span>
              <p className="text-xl font-bold font-mono text-[#F8FAFC] mt-1">{mission.recon_summary.links}</p>
            </div>
            <div className="bg-[#0E1217] border-2 border-black p-3.5 rounded shadow-[2px_2px_0px_#000000]">
              <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider">Meta Tags</span>
              <p className="text-xl font-bold font-mono text-[#F8FAFC] mt-1">{mission.recon_summary.meta_tags}</p>
            </div>
          </div>
          {(mission.recon_summary.is_spa || (mission.recon_summary.forms === 0 && mission.recon_summary.inputs === 0 && mission.recon_summary.scripts > 0)) && (
            <div className="flex items-start gap-3 p-3.5 rounded bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000000] text-xs text-[#CBD5E1]">
              <Sparkles className="w-4 h-4 text-[#E2F952] shrink-0 mt-0.5" />
              <div>
                <span className="font-bold text-[#F8FAFC] block font-mono">Client-Side Rendered (SPA) Application</span>
                Target renders UI elements dynamically in the browser DOM via JavaScript bundles. Interactive components (forms, inputs, buttons) are mounted at client runtime rather than static server HTML.
              </div>
            </div>
          )}
        </div>

        {/* Section 3 — Feature Summary & Attack Surface */}
        <div className="bg-[#141A23] border-2 border-black p-5 rounded shadow-[4px_4px_0px_#000000] space-y-5">
          <div className="flex items-center justify-between border-b-2 border-black pb-3">
            <h3 className="text-sm font-bold text-[#F8FAFC] flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#E2F952]" /> <span>Surface </span><span className="font-editorial italic font-normal text-[#E2F952]">Capabilities</span>
            </h3>
            <span className="text-[10px] font-mono text-[#94A3B8] bg-[#0E1217] px-2 py-0.5 rounded border border-black">
              {mission.features.length} Components
            </span>
          </div>
          <div className="space-y-2.5 max-h-[220px] overflow-y-auto pr-2">
            {mission.features.length === 0 ? (
              <p className="text-xs text-[#64748B] italic py-4">No classified components detected yet.</p>
            ) : (
              mission.features.map((f, idx) => {
                const label = getCapabilityLabel(f.name);
                const findingsOnFeature = getCapabilityFindings(f.name, mission.findings);
                const featHasCritical = findingsOnFeature.some(item => item.severity?.toLowerCase() === "critical");
                const featHasHigh = findingsOnFeature.some(item => item.severity?.toLowerCase() === "high");
                const featHasMed = findingsOnFeature.some(item => item.severity?.toLowerCase() === "medium");

                return (
                  <div key={idx} className="flex justify-between items-center p-3 rounded bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000000]">
                    <div className="flex items-center gap-2.5">
                      <div className={`w-2.5 h-2.5 rounded-full border border-black ${
                        findingsOnFeature.length > 0 
                          ? (featHasCritical ? "bg-[#DC2626]" : featHasHigh ? "bg-[#EF4444]" : "bg-[#F59E0B]")
                          : "bg-[#10B981]"
                      }`}></div>
                      <div>
                        <span className="text-xs font-bold text-[#F8FAFC] block">{label}</span>
                        <span className="text-[10px] text-[#94A3B8] font-mono">
                          {findingsOnFeature.length > 0 ? `${findingsOnFeature.length} finding${findingsOnFeature.length > 1 ? 's' : ''} identified` : "Component evaluated clean"}
                        </span>
                      </div>
                    </div>
                    <span className={`text-[10px] font-mono font-black px-2 py-0.5 rounded border border-black shadow-[1.5px_1.5px_0px_#000000] ${
                      findingsOnFeature.length > 0
                        ? (featHasCritical
                            ? "text-black bg-[#DC2626]"
                            : featHasHigh 
                            ? "text-black bg-[#EF4444]" 
                            : "text-black bg-[#F59E0B]")
                        : "text-black bg-[#10B981]"
                    }`}>
                      {findingsOnFeature.length > 0 
                        ? (featHasCritical ? "Critical Risk" : featHasHigh ? "High Risk" : featHasMed ? "Moderate Risk" : "Hardening")
                        : "Clean"}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Grid: OWASP 2025 Risk Profile and Timeline */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Section 4 — Security Posture & OWASP Top 10 Risk Mapping */}
        {(() => {
          const hasCritical = mission.findings.some(f => f.severity?.toLowerCase() === "critical");
          const hasHigh = mission.findings.some(f => f.severity?.toLowerCase() === "high");
          const hasMedium = mission.findings.some(f => f.severity?.toLowerCase() === "medium");

          const owaspMap = new Map<string, string>();
          mission.findings.forEach(f => {
            const owasp = getOwaspCategory(f.category);
            owaspMap.set(owasp.code, owasp.name);
          });
          const activeOwasp = Array.from(owaspMap.entries()).map(([code, name]) => ({ code, name }));

          return (
            <div className="bg-[#141A23] border-2 border-black p-5 rounded shadow-[4px_4px_0px_#000000] space-y-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between border-b-2 border-black pb-3">
                  <h3 className="text-sm font-bold text-[#F8FAFC] flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-[#EF4444]" /> OWASP Top 10 Risk Mapping
                  </h3>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider border-2 border-black shadow-[2px_2px_0px_#000000] ${
                    hasCritical ? "bg-[#DC2626] text-black" :
                    hasHigh ? "bg-[#EF4444] text-white" :
                    hasMedium ? "bg-[#F59E0B] text-black" :
                    "bg-[#10B981] text-black"
                  }`}>
                    {hasCritical ? "Critical Exposure" : hasHigh ? "High Risk Surface" : hasMedium ? "Moderate Risk" : "Hardened"}
                  </span>
                </div>

                <p className="text-xs text-[#94A3B8] mt-3 leading-relaxed">
                  Discovered findings are aligned with the <strong className="text-[#F8FAFC]">OWASP Top 10: 2025</strong> framework to prioritize defensive remediation.
                </p>

                <div className="mt-4 space-y-2">
                  {activeOwasp.length === 0 ? (
                    <div className="p-3 bg-[#0E1217] border-2 border-black rounded shadow-[2px_2px_0px_#000000] text-center text-xs text-[#64748B] italic">
                      No OWASP Top 10 vulnerabilities detected in current scope.
                    </div>
                  ) : (
                    activeOwasp.map((cat, i) => (
                      <div key={i} className="flex items-center justify-between p-2.5 bg-[#0E1217] border-2 border-black rounded shadow-[2px_2px_0px_#000000]">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono font-black text-black bg-[#E2F952] px-1.5 py-0.5 rounded border border-black shadow-[1px_1px_0px_#000000]">
                            {cat.code}
                          </span>
                          <span className="text-xs font-medium text-[#F8FAFC]">{cat.name}</span>
                        </div>
                        <span className="text-[10px] font-black text-black bg-[#EF4444] px-2 py-0.5 rounded border border-black shadow-[1px_1px_0px_#000000]">
                          Active
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="pt-3 border-t-2 border-black flex items-center justify-between text-xs">
                <span className="text-[#94A3B8]">Audit Perimeter:</span>
                <span className="font-bold text-[#10B981] flex items-center gap-1 font-mono">
                  <ShieldCheck className="w-3.5 h-3.5" /> 100% Scope Audited
                </span>
              </div>
            </div>
          );
        })()}

        {/* Section 5 — Mission Timeline */}
        <div className="bg-[#141A23] border-2 border-black p-5 rounded shadow-[4px_4px_0px_#000000] xl:col-span-2 space-y-5">
          <h3 className="text-sm font-bold text-[#F8FAFC] border-b-2 border-black pb-3 flex items-center gap-2">
            <Clock className="w-4 h-4 text-[#E2F952]" /> <span>Execution </span><span className="font-editorial italic font-normal text-[#E2F952]">Timeline</span>
          </h3>
          <div className="space-y-3 max-h-[250px] overflow-y-auto pr-2">
            {!timeline || timeline.length === 0 ? (
              <p className="text-xs text-[#64748B] italic py-4">No task logs available for this mission.</p>
            ) : (
              timeline.map((t, idx) => (
                <div key={idx} className="flex items-center justify-between p-3 bg-[#0E1217] border-2 border-black rounded shadow-[2px_2px_0px_#000000]">
                  <div className="flex items-center gap-3">
                    <div className={`w-2.5 h-2.5 rounded-full border border-black ${
                      t.status === "completed" ? "bg-[#10B981]" :
                      t.status === "failed" ? "bg-[#EF4444]" : (t.status as string) === "unavailable" ? "bg-[#64748B]" : "bg-[#F59E0B] animate-pulse"
                    }`}></div>
                    <span className="text-xs font-mono font-bold text-[#F8FAFC]">{getTaskLabel(t.task)}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className={`text-[10px] font-black uppercase tracking-wider px-2 py-0.5 rounded border border-black shadow-[1px_1px_0px_#000000] ${
                      t.status === "completed" ? "text-black bg-[#10B981]" :
                      t.status === "failed" ? "text-white bg-[#EF4444]" : (t.status as string) === "unavailable" ? "text-white bg-[#64748B]" : "text-black bg-[#F59E0B]"
                    }`}>{t.status}</span>
                    <span className="text-[10px] font-mono text-[#94A3B8]">
                      {new Date(t.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Section 6 — Findings list */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b-2 border-black pb-3">
          <h3 className="text-sm font-bold text-[#F8FAFC] flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-[#E2F952]" /> <span>Security </span><span className="font-editorial italic font-normal text-[#E2F952]">Findings</span> ({mission.findings.length})
          </h3>
          <span className="text-xs text-[#94A3B8]">Click any card to inspect reasoning and evidence logs</span>
        </div>

        <div className="space-y-3">
          {mission.findings.length === 0 ? (
            <div className="p-8 text-center bg-[#141A23] border-2 border-black rounded shadow-[3px_3px_0px_#000000] text-xs text-[#94A3B8]">
              No security weaknesses were detected for this route perimeter.
            </div>
          ) : (
            mission.findings.map(f => {
              const isExpanded = !!expandedFindings[f.finding_id];
              const sev = f.severity?.toLowerCase();
              const badgeBg = sev === "critical" ? "bg-[#DC2626] text-black" : sev === "high" ? "bg-[#EF4444] text-white" : sev === "medium" ? "bg-[#F59E0B] text-black" : "bg-[#10B981] text-black";

              return (
                <div
                  key={f.finding_id}
                  className="border-2 border-black rounded bg-[#141A23] p-5 shadow-[3px_3px_0px_#000000] transition-all"
                >
                  <div
                    className="flex justify-between items-center cursor-pointer select-none"
                    onClick={() => toggleFinding(f.finding_id)}
                  >
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wide border border-black shadow-[1.5px_1.5px_0px_#000000] ${badgeBg}`}>
                        {f.severity}
                      </span>
                      {f.model_severity ? (
                        <span
                          className="px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wide border border-black shadow-[1.5px_1.5px_0px_#000000] bg-[#1E293B] text-[#38BDF8]"
                          title="Second opinion from the Nuclei-trained TF-IDF + linear SVM severity model"
                        >
                          ML: {f.model_severity}
                        </span>
                      ) : mission.status === "running" ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border border-dashed border-[#64748B] text-[#64748B] animate-pulse">
                          ML pending
                        </span>
                      ) : (
                        <span
                          className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border border-black shadow-[1.5px_1.5px_0px_#000000] bg-[#374151] text-[#9CA3AF]"
                          title="The ML severity model produced no verdict for this finding (unavailable or no prediction)"
                        >
                          ML unavailable
                        </span>
                      )}
                      <h4 className="text-xs font-bold text-[#F8FAFC]">{f.title}</h4>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[11px] font-mono text-[#94A3B8]">{f.finding_id}</span>
                      {isExpanded ? <ChevronUp className="w-4 h-4 text-[#94A3B8]" /> : <ChevronDown className="w-4 h-4 text-[#94A3B8]" />}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="mt-4 pt-4 border-t-2 border-black space-y-4 text-xs animate-fadeIn">
                      <div>
                        <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider block mb-1">Description</span>
                        <p className="text-[#CBD5E1] leading-relaxed">{f.description}</p>
                      </div>

                      {f.reasoning && (
                        <div>
                          <span className="text-[10px] font-black text-[#E2F952] uppercase tracking-wider flex items-center gap-1.5 mb-1.5">
                            <Sparkles className="w-3.5 h-3.5 text-[#E2F952]" /> Explainable Security Reasoning
                          </span>
                          <div className="p-3.5 rounded bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000000] text-[#F8FAFC]">
                            <p className="leading-relaxed font-editorial italic text-sm">{f.reasoning}</p>
                          </div>
                        </div>
                      )}

                      {f.model_severity ? (
                        <div>
                          <span className="text-[10px] font-black text-[#38BDF8] uppercase tracking-wider block mb-1">ML Severity Model Verdict</span>
                          <div className="p-3.5 rounded bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000000] text-[#CBD5E1]">
                            <p className="leading-relaxed">
                              The Nuclei-trained TF-IDF + linear SVM rates this finding <strong className="text-[#F8FAFC] uppercase">{f.model_severity}</strong>.
                              This is a second opinion trained on Nuclei template ratings, not a validated severity for scanner findings.
                            </p>
                          </div>
                        </div>
                      ) : mission.status !== "running" ? (
                        <div>
                          <span className="text-[10px] font-black text-[#9CA3AF] uppercase tracking-wider block mb-1">ML Severity Model Verdict</span>
                          <div className="p-3.5 rounded bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000000] text-[#94A3B8]">
                            <p className="leading-relaxed">The ML severity model produced no verdict for this finding (model unavailable or no prediction returned).</p>
                          </div>
                        </div>
                      ) : null}

                      {f.recommendation && (
                        <div>
                          <span className="text-[10px] font-black text-[#10B981] uppercase tracking-wider block mb-1">Recommended Remediation</span>
                          <div className="p-3.5 rounded bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000000] text-[#CBD5E1]">
                            <p className="leading-relaxed">{f.recommendation}</p>
                          </div>
                        </div>
                      )}

                      {f.evidence && f.evidence.length > 0 && (
                        <div>
                          <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider block mb-1">Evidence</span>
                          <div className="bg-[#090D16] border-2 border-black p-3 rounded shadow-[2px_2px_0px_#000000] space-y-1 font-mono text-[10px] text-[#E2F952]">
                            {f.evidence.map((ev, i) => (
                              <div key={i} className="flex gap-2">
                                <span className="text-[#64748B] select-none">{i + 1}.</span>
                                <span className="break-all">{ev}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
