import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import OwnershipModal from "../components/OwnershipModal";
import type { TimelineTask, MissionDetail } from "../types";
import {
  Play,
  CheckCircle2,
  XCircle,
  Loader2,
  Globe,
  ArrowRight,
  ShieldCheck,
  Compass,
  Cpu,
  Zap,
  Layers,
  FileText,
  RotateCcw,
  Sparkles
} from "lucide-react";

type StepKey = "recon" | "feature_extraction" | "efficient_fetch" | "analysis" | "report_generation";

interface StepConfig {
  key: StepKey;
  label: string;
  taskName: string;
  description: string;
  activeStatusText: string;
  icon: React.ReactNode;
}

function normalizeTargetUrl(input: string) {
  const value = input.trim();
  if (!value) {
    return value;
  }

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return value;
  }

  return `https://${value}`;
}

const STEPS: StepConfig[] = [
  {
    key: "recon",
    label: "Reconnaissance & Route Crawl",
    taskName: "RUN_RECON",
    description: "Discover endpoints, HTTP headers, inputs, forms, and interactive buttons",
    activeStatusText: "Crawling web routes, extracting DOM structures & security headers...",
    icon: <Compass className="w-4 h-4" />
  },
  {
    key: "feature_extraction",
    label: "Feature Extraction",
    taskName: "EXTRACT_FEATURES",
    description: "Categorize page structures into security features using AI",
    activeStatusText: "Classifying attack surface and security features with LLM reasoning...",
    icon: <Layers className="w-4 h-4" />
  },
  {
    key: "efficient_fetch",
    label: "Contextual Surface Retrieval",
    taskName: "RUN_EFFICIENT_FETCH",
    description: "Extract focused structural contexts and evaluate relevant attack surfaces",
    activeStatusText: "Performing semantic structure ranking and contextual surface extraction...",
    icon: <Zap className="w-4 h-4" />
  },
  {
    key: "analysis",
    label: "Security Analysis",
    taskName: "RUN_ANALYSIS",
    description: "Inspect targeted structures for vulnerabilities and misconfigurations",
    activeStatusText: "Analyzing security evidence, headers, CSRF & authentication surfaces...",
    icon: <Cpu className="w-4 h-4" />
  },
  {
    key: "report_generation",
    label: "Report Generation",
    taskName: "GENERATE_REPORT",
    description: "Synthesize findings into executive summary, risk score & remediation advice",
    activeStatusText: "Compiling executive security reconnaissance report & recommendations...",
    icon: <FileText className="w-4 h-4" />
  }
];

const SAMPLE_TARGETS = [
  "https://www.hariomlightings.com/",
  "https://vynoa.in",
  "https://example.com"
];

export default function NewScan() {
  const [url, setUrl] = useState("");
  const [maxPages, setMaxPages] = useState(5);
  const [error, setError] = useState("");
  const [ownershipBlock, setOwnershipBlock] = useState<{ code: string; message: string; url: string } | null>(null);
  const [scanning, setScanning] = useState(false);
  const [missionId, setMissionId] = useState<string | null>(null);
  const [timeline, setTimeline] = useState<Record<StepKey, "pending" | "running" | "completed" | "failed">>({
    recon: "pending",
    feature_extraction: "pending",
    efficient_fetch: "pending",
    analysis: "pending",
    report_generation: "pending"
  });

  const [overallStatus, setOverallStatus] = useState<"running" | "completed" | "failed" | null>(null);
  const [missionDetail, setMissionDetail] = useState<MissionDetail | null>(null);

  // Validate URL and start scan
  const handleStartScan = async (e?: React.FormEvent, customUrl?: string) => {
    if (e) e.preventDefault();
    setError("");

    const targetUrl = normalizeTargetUrl(customUrl || url);
    if (!targetUrl) {
      setError("Please enter a valid target URL");
      return;
    }

    try {
      setScanning(true);
      setOverallStatus("running");
      setMissionDetail(null);
      
      // Step 1 starts in running state immediately
      setTimeline({
        recon: "running",
        feature_extraction: "pending",
        efficient_fetch: "pending",
        analysis: "pending",
        report_generation: "pending"
      });

      const res = await api.startScan(targetUrl, maxPages);
      setMissionId(res.mission_id);
      if (customUrl) setUrl(customUrl);
    } catch (err: any) {
      const code = err && err.code;
      if (code === "OWNERSHIP_VERIFICATION_REQUIRED" || code === "AUTH_WEAK_IDENTITY") {
        setOwnershipBlock({ code, message: err.message || "Ownership verification required", url: targetUrl });
      } else {
        setError(err.message || "Failed to initiate scan");
      }
      setScanning(false);
      setOverallStatus(null);
    }
  };

  // Fast polling (500ms) for real-time stepper updates
  useEffect(() => {
    if (!missionId) return;

    let isMounted = true;

    const poll = async () => {
      try {
        const [tasks, detail] = await Promise.all([
          api.getMissionTimeline(missionId) as Promise<TimelineTask[]>,
          api.getMissionDetail(missionId) as Promise<MissionDetail>
        ]);

        if (!isMounted) return;

        setOverallStatus(detail.status);
        if (detail.status === "completed" || detail.status === "failed") {
          setMissionDetail(detail);
        }

        const newTimeline = { ...timeline };

        if (detail.status === "completed") {
          // All steps completed
          STEPS.forEach(s => {
            newTimeline[s.key] = "completed";
          });
        } else if (detail.status === "failed") {
          // Mark completed ones, and mark the failed one
          let foundFailed = false;
          STEPS.forEach(step => {
            const matchedTask = tasks.find(t => t.task === step.taskName);
            if (matchedTask?.status === "completed") {
              newTimeline[step.key] = "completed";
            } else if (matchedTask?.status === "failed" || !foundFailed) {
              newTimeline[step.key] = "failed";
              foundFailed = true;
            } else {
              newTimeline[step.key] = "pending";
            }
          });
        } else {
          // Running status: evaluate steps dynamically
          let firstPendingFound = false;

          STEPS.forEach((step) => {
            const matchedTask = tasks.find(t => t.task === step.taskName);
            if (matchedTask?.status === "completed") {
              newTimeline[step.key] = "completed";
            } else if (matchedTask?.status === "failed") {
              newTimeline[step.key] = "failed";
            } else if (matchedTask?.status === "running" || matchedTask?.status === "pending") {
              newTimeline[step.key] = "running";
              firstPendingFound = true;
            } else if (!firstPendingFound) {
              // This is the active next step in progress
              newTimeline[step.key] = "running";
              firstPendingFound = true;
            } else {
              newTimeline[step.key] = "pending";
            }
          });
        }

        setTimeline(newTimeline);
      } catch (err) {
        console.error("Error polling scan timeline", err);
      }
    };

    const pollInterval = setInterval(poll, 500);
    // Execute immediately on mount/missionId set
    poll();

    return () => {
      isMounted = false;
      clearInterval(pollInterval);
    };
  }, [missionId]);

  // Compute completed percentage
  const completedCount = STEPS.filter(s => timeline[s.key] === "completed").length;
  const progressPercent = overallStatus === "completed" ? 100 : Math.round((completedCount / STEPS.length) * 100);

  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-fadeIn">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 bg-[#E2F952] border-2 border-black shadow-[2.5px_2.5px_0px_#000] flex items-center justify-center text-black font-bold">
            <Play className="w-5 h-5 fill-black" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold text-[#F8FAFC]">
              Launch Target Scan
            </h1>
            <p className="text-xs sm:text-sm text-[#94A3B8] mt-0.5">
              Initiate an automated <span className="font-editorial italic text-[#E2F952]">agentic security reconnaissance</span> mission using the smart orchestrator pipeline.
            </p>
          </div>
        </div>
      </div>

      {/* Input panel (When not scanning) */}
      {!scanning ? (
        <div className="bg-[#141A23] border-2 border-black shadow-[4px_4px_0px_#000] p-8 space-y-6">
          <form onSubmit={handleStartScan} className="space-y-6">
            <div className="space-y-2.5">
              <label htmlFor="url" className="text-sm font-bold text-[#F8FAFC] flex items-center justify-between">
                <span>Target URL</span>
                <span className="text-xs font-normal text-[#94A3B8] font-editorial italic">Supports HTTP / HTTPS web applications</span>
              </label>
              <div className="relative group">
                <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-[#94A3B8] group-focus-within:text-[#E2F952] transition-colors" />
                <input
                  id="url"
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] pl-12 pr-4 py-3.5 text-sm text-[#F8FAFC] placeholder-[#64748B] focus:border-black focus:shadow-[4px_4px_0px_#000] outline-none transition-all font-mono"
                />
              </div>
              {error && <p className="text-xs text-[#EF4444] font-medium mt-1 flex items-center gap-1.5"><XCircle className="w-3.5 h-3.5" /> {error}</p>}
              <button type="button" onClick={() => setUrl("http://localhost:8080")} className="text-xs text-[#3B82F6] underline mt-1">Demo Details</button>
            </div>

            {/* Quick Sample Targets */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-[#94A3B8] uppercase tracking-wider">Quick Select Sample Targets:</span>
              <div className="flex flex-wrap gap-2">
                {SAMPLE_TARGETS.map(sample => (
                  <button
                    key={sample}
                    type="button"
                    onClick={() => {
                      setUrl(sample);
                      handleStartScan(undefined, sample);
                    }}
                    className="px-3 py-1.5 bg-[#0E1217] hover:bg-[#1C2533] border-2 border-black shadow-[2px_2px_0px_#000] hover:shadow-[3px_3px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-xs font-mono text-[#CBD5E1] hover:text-[#E2F952] transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <Globe className="w-3 h-3 text-[#E2F952]" />
                    {sample}
                  </button>
                ))}
              </div>
            </div>

            {/* Crawl Scope Selector */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-[#94A3B8] uppercase tracking-wider flex items-center justify-between">
                <span>Crawl Scope (Max Routes)</span>
                <span className="text-xs text-[#E2F952] font-mono font-bold">{maxPages} {maxPages === 1 ? "Route" : "Routes"}</span>
              </label>
              <div className="grid grid-cols-5 gap-2">
                {[1, 3, 5, 10, 15].map((pages) => (
                  <button
                    key={pages}
                    type="button"
                    onClick={() => setMaxPages(pages)}
                    className={`py-2 px-2 text-xs font-mono font-bold border-2 border-black transition-all text-center cursor-pointer ${
                      maxPages === pages
                        ? "bg-[#E2F952] text-black shadow-[2.5px_2.5px_0px_#000] -translate-y-0.5"
                        : "bg-[#0E1217] text-[#94A3B8] shadow-[1.5px_1.5px_0px_#000] hover:text-[#F8FAFC] hover:bg-[#1C2533]"
                    }`}
                  >
                    {pages} {pages === 1 ? "Page" : "Pages"}
                  </button>
                ))}
              </div>
            </div>

            <button
              type="submit"
              className="w-full brutal-btn-primary py-3.5 text-sm flex items-center justify-center gap-2 cursor-pointer font-bold tracking-wide"
            >
              <Play className="w-4 h-4 fill-black" /> Launch Security Reconnaissance
            </button>
          </form>

          {/* Pipeline overview info */}
          <div className="pt-6 border-t-2 border-black grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-[#94A3B8]">
            <div className="flex items-start gap-2.5 p-3.5 bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000]">
              <Compass className="w-4 h-4 text-[#38BDF8] shrink-0 mt-0.5" />
              <div>
                <strong className="text-[#F8FAFC] block mb-0.5">Recursive Crawling</strong>
                Discovers forms, input fields, scripts, and endpoints.
              </div>
            </div>
            <div className="flex items-start gap-2.5 p-3.5 bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000]">
              <Cpu className="w-4 h-4 text-[#C084FC] shrink-0 mt-0.5" />
              <div>
                <strong className="text-[#F8FAFC] block mb-0.5">AI Security Reasoning</strong>
                Categorizes attack surface and identifies vulnerability evidence.
              </div>
            </div>
            <div className="flex items-start gap-2.5 p-3.5 bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000]">
              <Zap className="w-4 h-4 text-[#E2F952] shrink-0 mt-0.5" />
              <div>
                <strong className="text-[#F8FAFC] block mb-0.5">Efficient Fetch</strong>
                Reduces LLM tokens by ~50%+ via selective chunking.
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Progress Timeline panel */
        <div className="bg-[#141A23] border-2 border-black shadow-[6px_6px_0px_#000] p-8 space-y-8 animate-fadeIn">
          {/* Top Status Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b-2 border-black">
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <span className="font-mono text-xs font-bold text-black bg-[#E2F952] px-2.5 py-1 border-2 border-black shadow-[2px_2px_0px_#000]">
                  {missionId || "INITIALIZING..."}
                </span>
                <span className="text-xs text-[#94A3B8]">•</span>
                <span className="text-sm font-medium text-[#F8FAFC] truncate max-w-md font-mono" title={url}>
                  {url}
                </span>
              </div>
              <div className="flex items-center gap-2 mt-2.5">
                <span className="text-xs text-[#94A3B8]">Mission Status:</span>
                {overallStatus === "running" && (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 text-xs font-mono font-bold bg-[#38BDF8]/20 border border-black shadow-[1px_1px_0px_#000] text-[#38BDF8]">
                    <Loader2 className="w-3 h-3 animate-spin" /> SCAN IN PROGRESS ({progressPercent}%)
                  </span>
                )}
                {overallStatus === "completed" && (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 text-xs font-mono font-bold bg-[#10B981]/20 border border-black shadow-[1px_1px_0px_#000] text-[#10B981]">
                    <CheckCircle2 className="w-3.5 h-3.5" /> COMPLETED (100%)
                  </span>
                )}
                {overallStatus === "failed" && (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 text-xs font-mono font-bold bg-[#EF4444]/20 border border-black shadow-[1px_1px_0px_#000] text-[#EF4444]">
                    <XCircle className="w-3.5 h-3.5" /> SCAN ABORTED
                  </span>
                )}
              </div>
            </div>

            {/* Top Quick Reset Action */}
            <button
              onClick={() => {
                setScanning(false);
                setUrl("");
                setMissionId(null);
                setOverallStatus(null);
                setMissionDetail(null);
              }}
              className="self-start sm:self-auto px-3.5 py-1.5 text-xs text-[#CBD5E1] hover:text-white bg-[#0E1217] hover:bg-[#1C2533] border-2 border-black shadow-[2px_2px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] transition-all flex items-center gap-1.5 cursor-pointer font-bold"
              title="Reset and start a new scan"
            >
              <RotateCcw className="w-3 h-3" /> New Target
            </button>
          </div>

          {/* Progress Bar */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs text-[#94A3B8]">
              <span className="font-mono">Pipeline Progress</span>
              <span className="font-bold text-[#F8FAFC] font-mono">{completedCount} of 5 Workers Finished</span>
            </div>
            <div className="w-full h-3 bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  overallStatus === "failed"
                    ? "bg-[#EF4444]"
                    : overallStatus === "completed"
                    ? "bg-[#10B981]"
                    : "bg-[#E2F952]"
                }`}
                style={{ width: `${Math.max(8, progressPercent)}%` }}
              ></div>
            </div>
          </div>

          {/* Timeline Stepper */}
          <div className="space-y-4">
            {STEPS.map((step, idx) => {
              const status = timeline[step.key];
              const isLast = idx === STEPS.length - 1;
              
              return (
                <div key={step.key} className="flex gap-4 relative group">
                  {/* Connector Line */}
                  {!isLast && (
                    <div
                      className={`absolute left-[20px] top-10 w-[2px] h-[calc(100%-10px)] transition-colors duration-200 ${
                        status === "completed"
                          ? "bg-black"
                          : "bg-black/50"
                      }`}
                    ></div>
                  )}

                  {/* Step status indicator */}
                  <div className="z-10 shrink-0">
                    {status === "completed" ? (
                      <div className="w-10 h-10 border-2 border-black bg-[#10B981] text-black shadow-[2px_2px_0px_#000] flex items-center justify-center font-bold">
                        <CheckCircle2 className="w-5 h-5 text-black" />
                      </div>
                    ) : status === "failed" ? (
                      <div className="w-10 h-10 border-2 border-black bg-[#EF4444] text-white shadow-[2px_2px_0px_#000] flex items-center justify-center font-bold">
                        <XCircle className="w-5 h-5 text-white" />
                      </div>
                    ) : status === "running" ? (
                      <div className="w-10 h-10 border-2 border-black bg-[#E2F952] text-black shadow-[2px_2px_0px_#000] flex items-center justify-center font-bold">
                        <Loader2 className="w-5 h-5 animate-spin text-black" />
                      </div>
                    ) : (
                      <div className="w-10 h-10 border-2 border-black bg-[#0E1217] text-[#94A3B8] shadow-[1.5px_1.5px_0px_#000] flex items-center justify-center font-mono font-bold">
                        <span className="text-xs">{idx + 1}</span>
                      </div>
                    )}
                  </div>

                  {/* Step Info */}
                  <div className={`flex-1 p-4 border-2 border-black transition-all ${
                    status === "running"
                      ? "bg-[#18202C] shadow-[3.5px_3.5px_0px_#000] -translate-y-0.5"
                      : status === "completed"
                      ? "bg-[#0E1217] shadow-[2px_2px_0px_#000]"
                      : "bg-[#0E1217]/50 shadow-[1px_1px_0px_#000]"
                  }`}>
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2">
                        <span className={`p-1 ${
                          status === "completed" ? "text-[#10B981]" : status === "running" ? "text-[#E2F952]" : "text-[#64748B]"
                        }`}>
                          {step.icon}
                        </span>
                        <h4 className={`text-sm font-bold ${
                          status === "running"
                            ? "text-[#E2F952]"
                            : status === "completed"
                            ? "text-[#F8FAFC]"
                            : status === "failed"
                            ? "text-[#EF4444]"
                            : "text-[#64748B]"
                        }`}>
                          {step.label}
                        </h4>
                      </div>

                      {/* Status Badges */}
                      {status === "running" && (
                        <span className="text-[11px] bg-[#E2F952] text-black border border-black shadow-[1px_1px_0px_#000] px-2 py-0.5 font-mono font-bold flex items-center gap-1.5">
                          <Loader2 className="w-3 h-3 animate-spin" /> In Progress
                        </span>
                      )}
                      {status === "completed" && (
                        <span className="text-[11px] bg-[#10B981]/20 border border-black shadow-[1px_1px_0px_#000] text-[#10B981] px-2 py-0.5 font-mono font-bold flex items-center gap-1">
                          Done
                        </span>
                      )}
                      {status === "failed" && (
                        <span className="text-[11px] bg-[#EF4444]/20 border border-black shadow-[1px_1px_0px_#000] text-[#EF4444] px-2 py-0.5 font-mono font-bold">
                          Failed
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-[#94A3B8] mt-1 pl-7">
                      {status === "running" ? (
                        <span className="text-[#38BDF8] font-mono font-medium flex items-center gap-1.5">
                          {step.activeStatusText}
                        </span>
                      ) : (
                        step.description
                      )}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Quick Stats Summary when Completed */}
          {overallStatus === "completed" && missionDetail && (
            <div className="p-5 bg-[#0E1217] border-2 border-black shadow-[4px_4px_0px_#000] space-y-4 animate-fadeIn">
              <div className="flex items-center gap-2 text-xs font-mono font-bold uppercase tracking-wider text-[#E2F952]">
                <Sparkles className="w-4 h-4 text-[#E2F952]" /> Scan Summary & Findings Ready
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                <div className="p-3 bg-[#141A23] border-2 border-black shadow-[2px_2px_0px_#000]">
                  <div className="text-lg font-bold text-[#38BDF8] font-mono">
                    {missionDetail.recon_summary?.routes || 1}
                  </div>
                  <div className="text-[11px] text-[#94A3B8] mt-0.5">Routes Crawled</div>
                </div>
                <div className="p-3 bg-[#141A23] border-2 border-black shadow-[2px_2px_0px_#000]">
                  <div className="text-lg font-bold text-[#C084FC] font-mono">
                    {missionDetail.features?.length || 1}
                  </div>
                  <div className="text-[11px] text-[#94A3B8] mt-0.5">Features Extracted</div>
                </div>
                <div className="p-3 bg-[#141A23] border-2 border-black shadow-[2px_2px_0px_#000]">
                  <div className="text-lg font-bold text-[#EF4444] font-mono">
                    {missionDetail.findings?.length || 0}
                  </div>
                  <div className="text-[11px] text-[#94A3B8] mt-0.5">Findings Identified</div>
                </div>
                <div className="p-3 bg-[#141A23] border-2 border-black shadow-[2px_2px_0px_#000]">
                  <div className="text-lg font-bold text-[#E2F952] font-mono">
                    {missionDetail.runtime || "Complete"}
                  </div>
                  <div className="text-[11px] text-[#94A3B8] mt-0.5">Scan Runtime</div>
                </div>
              </div>
            </div>
          )}

          {/* Bottom Actions Bar */}
          {overallStatus !== "running" && (
            <div className="pt-6 border-t-2 border-black flex flex-col-reverse sm:flex-row items-center justify-between gap-3">
              <button
                onClick={() => {
                  setScanning(false);
                  setUrl("");
                  setMissionId(null);
                  setOverallStatus(null);
                  setMissionDetail(null);
                }}
                className="w-full sm:w-auto px-5 py-2.5 brutal-btn-secondary text-xs font-bold flex items-center justify-center gap-2 cursor-pointer"
              >
                <RotateCcw className="w-4 h-4" /> Scan Another URL
              </button>

              {overallStatus === "completed" && missionId && (
                <Link
                  to={`/mission/${missionId}`}
                  className="w-full sm:w-auto px-7 py-3 brutal-btn-primary text-xs font-bold flex items-center justify-center gap-2 cursor-pointer"
                >
                  <ShieldCheck className="w-4 h-4 text-black" /> Inspect Report <ArrowRight className="w-4 h-4 text-black" />
                </Link>
              )}

              {overallStatus === "failed" && (
                <button
                  onClick={() => handleStartScan(undefined, url)}
                  className="w-full sm:w-auto px-6 py-2.5 bg-[#EF4444] text-white border-2 border-black shadow-[3px_3px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-xs font-bold transition-all flex items-center justify-center gap-2 cursor-pointer"
                >
                  <RotateCcw className="w-4 h-4" /> Retry Scan
                </button>
              )}
            </div>
          )}
        </div>
      )}
      {ownershipBlock && (
        <OwnershipModal
          open={true}
          code={ownershipBlock.code}
          message={ownershipBlock.message}
          targetUrl={ownershipBlock.url}
          onClose={() => setOwnershipBlock(null)}
          onUseDemo={() => { setUrl("http://localhost:8080"); setOwnershipBlock(null); }}
          onVerified={() => { setOwnershipBlock(null); setError(""); }}
        />
      )}
    </div>
  );
}
