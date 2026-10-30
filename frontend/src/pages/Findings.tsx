import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../services/api";
import type { Finding } from "../types";
import SecurityMetricsStrip from "../components/common/SecurityMetricsStrip";
import {
  ShieldAlert,
  Search,
  SlidersHorizontal,
  X,
  ExternalLink,
  ClipboardCheck,
  Sparkles,
  ShieldCheck,
  Database,
  BrainCircuit,
  Layers,
  Compass,
  Cpu,
  RefreshCw,
  Zap
} from "lucide-react";

export default function Findings() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = searchParams.get("tab") === "memory" ? "memory" : "registry";

  const setActiveTab = (tab: "registry" | "memory") => {
    if (tab === "memory") {
      setSearchParams({ tab: "memory" });
    } else {
      setSearchParams({});
    }
  };

  // Findings Filters State
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [search, setSearch] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Semantic Search State
  const [searchQuery, setSearchQuery] = useState("");
  const [collection, setCollection] = useState("findings");
  const [searchResults, setSearchResults] = useState<any[] | null>(null);
  const [searching, setSearching] = useState(false);

  // 1. Fetch Findings Registry
  const { data: findings, isLoading: isFindingsLoading } = useQuery<Finding[]>({
    queryKey: ["findings", severity, category, search],
    queryFn: () => api.getFindings(severity, category, search),
    refetchInterval: 5000
  });

  // 2. Fetch Semantic Memory Summary
  const { data: memorySummary, isLoading: isMemoryLoading, refetch: refetchMemory } = useQuery({
    queryKey: ["memory-summary"],
    queryFn: api.getMemorySummary,
    refetchInterval: 10000
  });

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    try {
      setSearching(true);
      const res = await api.searchMemory(searchQuery, collection);
      setSearchResults(res.results || []);
    } catch (err) {
      console.error("Semantic search failed", err);
    } finally {
      setSearching(false);
    }
  };

  const getSeverityStyle = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case "critical":
        return "bg-[#DC2626]/10 text-[#DC2626] border-[#DC2626]/30";
      case "high":
        return "bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30";
      case "medium":
        return "bg-[#F59E0B]/10 text-[#F59E0B] border-[#F59E0B]/30";
      case "low":
        return "bg-[#EAB308]/10 text-[#EAB308] border-[#EAB308]/30";
      default:
        return "bg-[#38BDF8]/10 text-[#38BDF8] border-[#38BDF8]/30";
    }
  };

  const categories = [
    { label: "All Categories", value: "all" },
    { label: "CSRF Risks", value: "missing_csrf" },
    { label: "Weak Authentication", value: "weak_authentication" },
    { label: "Exposed Endpoints", value: "exposed_endpoint" },
    { label: "File Upload Risks", value: "file_upload_risk" },
    { label: "Security Headers", value: "missing_security_headers" },
    { label: "Admin Panels", value: "admin_surface" },
    { label: "Sensitive Inputs", value: "sensitive_input" },
    { label: "Vulnerable Dependencies", value: "vulnerable_dependency" },
    { label: "Subresource Integrity", value: "missing_subresource_integrity" },
    { label: "Verbose Error Leaks", value: "verbose_error_leak" },
  ];

  const totalCount = findings?.length ?? 0;
  const totalVectors =
    (memorySummary?.counts?.findings_indexed ?? 0) +
    (memorySummary?.counts?.features_indexed ?? 0) +
    (memorySummary?.counts?.routes_indexed ?? 0);

  return (
    <div className="space-y-8 animate-fadeIn relative min-h-screen">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b-2 border-black pb-6">
        <div>
          <div className="flex items-center gap-2.5 flex-wrap">
            <h1 className="text-2xl font-extrabold tracking-tight text-[#F8FAFC]">
              Security Findings Explorer
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 text-[11px] font-mono font-bold bg-[#141A23] text-[#38BDF8] border-2 border-black shadow-[1.5px_1.5px_0px_#000]">
              <ShieldAlert className="w-3.5 h-3.5 text-[#38BDF8]" />
              {totalCount} Active Findings
            </span>
            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-0.5 text-[11px] font-mono font-bold bg-[#141A23] text-[#C084FC] border-2 border-black shadow-[1.5px_1.5px_0px_#000]">
              <BrainCircuit className="w-3.5 h-3.5 text-[#C084FC]" />
              {totalVectors} Embedded Vectors
            </span>
          </div>
          <p className="text-xs text-[#94A3B8] mt-1 font-sans">
            Unified registry of discovered vulnerabilities, evidence logs, and <em className="font-editorial text-[#CBD5E1]">ChromaDB</em> semantic memory powering cross-mission intelligence.
          </p>
        </div>

        <div className="flex items-center gap-2 bg-[#141A23] border-2 border-black shadow-[2px_2px_0px_#000] px-3.5 py-2 text-xs text-[#CBD5E1] w-fit">
          <Sparkles className="w-4 h-4 text-[#E2F952] shrink-0" />
          <span><strong className="text-[#F8FAFC]">Explainable AI Active:</strong> Automated reasoning and semantic vector retrieval attached to each finding.</span>
        </div>
      </div>

      {/* Unified Platform Metrics Strip */}
      <SecurityMetricsStrip variant="full" />

      {/* Segmented View Switcher Tabs */}
      <div className="flex items-center gap-3 border-b-2 border-black pb-4">
        <button
          onClick={() => setActiveTab("registry")}
          className={`flex items-center gap-2.5 px-4 py-2.5 border-2 border-black text-xs font-bold transition-all cursor-pointer ${
            activeTab === "registry"
              ? "bg-[#E2F952] text-black shadow-[3px_3px_0px_#000] -translate-y-0.5"
              : "bg-[#141A23] text-[#94A3B8] shadow-[2px_2px_0px_#000] hover:text-[#F8FAFC] hover:bg-[#1C2533]"
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Active Findings Registry</span>
          <span className="ml-1 px-2 py-0.5 text-[10px] bg-black/20 text-inherit font-mono font-bold border border-black/30">
            {totalCount}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("memory")}
          className={`flex items-center gap-2.5 px-4 py-2.5 border-2 border-black text-xs font-bold transition-all cursor-pointer ${
            activeTab === "memory"
              ? "bg-[#E2F952] text-black shadow-[3px_3px_0px_#000] -translate-y-0.5"
              : "bg-[#141A23] text-[#94A3B8] shadow-[2px_2px_0px_#000] hover:text-[#F8FAFC] hover:bg-[#1C2533]"
          }`}
        >
          <BrainCircuit className="w-4 h-4" />
          <span>Semantic Memory & Vector Intelligence</span>
          <span className="ml-1 px-2 py-0.5 text-[10px] bg-black/20 text-inherit font-mono font-bold border border-black/30">
            {totalVectors} vectors
          </span>
        </button>
      </div>

      {/* ==================== TAB 1: ACTIVE FINDINGS REGISTRY ==================== */}
      {activeTab === "registry" && (
        <div className="space-y-6 animate-fadeIn">
          {/* Filters & Search Panel */}
          <div className="bg-[#141A23] border-2 border-black shadow-[3px_3px_0px_#000] p-5 space-y-4 md:space-y-0 md:flex md:items-center md:justify-between gap-4">
            {/* Search Input */}
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[#94A3B8]" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search findings by title, description, ID..."
                className="w-full bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] pl-10 pr-4 py-2 text-xs text-[#F8FAFC] placeholder-[#64748B] focus:border-black focus:shadow-[3px_3px_0px_#000] outline-none transition-all font-mono"
              />
            </div>

            {/* Dropdowns */}
            <div className="flex flex-wrap items-center gap-3">
              {/* Severity Filter */}
              <div className="flex items-center gap-2 bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] px-3 py-1.5 transition-all">
                <SlidersHorizontal className="w-3.5 h-3.5 text-[#94A3B8]" />
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  className="bg-[#0E1217] text-xs text-[#F8FAFC] font-semibold outline-none border-none cursor-pointer pr-1"
                >
                  <option value="all" className="bg-[#141A23] text-[#F8FAFC]">All Severities</option>
                  <option value="critical" className="bg-[#141A23] text-[#DC2626] font-semibold">Critical</option>
                  <option value="high" className="bg-[#141A23] text-[#EF4444] font-semibold">High</option>
                  <option value="medium" className="bg-[#141A23] text-[#F59E0B] font-semibold">Medium</option>
                  <option value="low" className="bg-[#141A23] text-[#EAB308] font-semibold">Low</option>
                  <option value="informational" className="bg-[#141A23] text-[#38BDF8] font-semibold">Informational</option>
                </select>
              </div>

              {/* Category Filter */}
              <div className="flex items-center gap-2 bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] px-3 py-1.5 transition-all">
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="bg-[#0E1217] text-xs text-[#F8FAFC] font-semibold outline-none border-none cursor-pointer pr-1"
                >
                  {categories.map((c) => (
                    <option key={c.value} value={c.value} className="bg-[#141A23] text-[#F8FAFC]">
                      {c.label}
                    </option>
                  ))}
                </select>
              </div>

              {(severity !== "all" || category !== "all" || search) && (
                <button
                  onClick={() => {
                    setSeverity("all");
                    setCategory("all");
                    setSearch("");
                  }}
                  className="px-2.5 py-1 text-xs text-[#EF4444] bg-[#0E1217] hover:bg-[#EF4444]/15 border-2 border-black shadow-[1.5px_1.5px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] transition-all font-bold cursor-pointer"
                >
                  Reset
                </button>
              )}
            </div>
          </div>

          {/* Findings Table */}
          <div className="bg-[#141A23] border-2 border-black shadow-[4px_4px_0px_#000] overflow-hidden">
            {isFindingsLoading ? (
              <div className="flex flex-col items-center justify-center py-24 text-center">
                <div className="w-10 h-10 border-2 border-t-transparent border-[#E2F952] animate-spin"></div>
                <span className="text-[#94A3B8] text-xs font-semibold mt-4 font-mono">Filtering observations...</span>
              </div>
            ) : !findings || findings.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 text-center space-y-2">
                <ShieldCheck className="w-12 h-12 text-[#10B981] stroke-1" />
                <p className="text-sm font-bold text-[#F8FAFC]">No matching findings detected.</p>
                <p className="text-xs text-[#94A3B8] font-editorial italic">Adjust filters above or launch a new reconnaissance scan against a target.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="bg-[#0E1217] border-b-2 border-black text-[#94A3B8] font-bold uppercase tracking-wider text-[10px]">
                      <th className="p-4">Finding ID</th>
                      <th className="p-4">Title & Reasoning Summary</th>
                      <th className="p-4">Severity</th>
                      <th className="p-4">Mission</th>
                      <th className="p-4">Confidence</th>
                      <th className="p-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-black/60">
                    {[...findings]
                      .sort((a, b) => {
                        const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };
                        const weightA = severityOrder[a.severity?.toLowerCase()] ?? 0;
                        const weightB = severityOrder[b.severity?.toLowerCase()] ?? 0;
                        return weightB - weightA;
                      })
                      .map((f) => (
                        <tr
                          key={f.finding_id}
                          className="hover:bg-[#18202C] transition-all cursor-pointer group"
                          onClick={() => setSelectedFinding(f)}
                        >
                          <td className="p-4 font-mono font-bold text-[#38BDF8] whitespace-nowrap text-[11px]">{f.finding_id}</td>
                          <td className="p-4">
                            <div className="font-bold text-[#F8FAFC]">{f.title}</div>
                            {f.reasoning && (
                              <div className="text-[11px] text-[#CBD5E1] font-editorial italic line-clamp-1 mt-1 flex items-center gap-1.5">
                                <Sparkles className="w-3 text-[#E2F952] shrink-0" />
                                <span className="truncate">{f.reasoning}</span>
                              </div>
                            )}
                          </td>
                          <td className="p-4 whitespace-nowrap">
                            <span className={`px-2 py-0.5 border border-black shadow-[1px_1px_0px_#000] text-[10px] font-mono font-bold uppercase tracking-wide ${getSeverityStyle(f.severity)}`}>
                              {f.severity}
                            </span>
                            {f.model_severity && (
                              <span
                                className="ml-1.5 px-2 py-0.5 border border-black shadow-[1px_1px_0px_#000] text-[10px] font-mono font-bold uppercase tracking-wide bg-[#1E293B] text-[#38BDF8]"
                                title="Second opinion from the Nuclei-trained TF-IDF + linear SVM severity model"
                              >
                                ML: {f.model_severity}
                              </span>
                            )}
                          </td>
                          <td className="p-4 font-mono text-[#94A3B8] whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                            <Link to={`/mission/${f.mission}`} className="hover:text-[#E2F952] hover:underline inline-flex items-center gap-1">
                              {f.mission} <ExternalLink className="w-3 h-3" />
                            </Link>
                          </td>
                          <td className="p-4 whitespace-nowrap">
                            <span className="font-mono text-[#10B981] font-bold text-[11px]">
                              {Math.round((f.confidence > 1 ? f.confidence : f.confidence * 100))}%
                            </span>
                          </td>
                          <td className="p-4 text-right whitespace-nowrap">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedFinding(f);
                              }}
                              className="px-3 py-1 bg-[#0E1217] group-hover:bg-[#E2F952] group-hover:text-black border border-black shadow-[1.5px_1.5px_0px_#000] active:translate-x-[1px] active:translate-y-[1px] text-[11px] font-mono font-bold text-[#CBD5E1] transition-all cursor-pointer"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================== TAB 2: SEMANTIC VECTOR MEMORY ==================== */}
      {activeTab === "memory" && (
        <div className="space-y-6 animate-fadeIn">
          {/* Top Memory Banner Actions */}
          <div className="flex items-center justify-between bg-[#141A23] border-2 border-black shadow-[3px_3px_0px_#000] p-5">
            <div>
              <h3 className="text-sm font-bold text-[#F8FAFC] flex items-center gap-2">
                <Database className="w-4 h-4 text-[#E2F952]" /> ChromaDB Vector RAG Store Status
              </h3>
              <p className="text-xs text-[#94A3B8] mt-0.5">
                Multi-collection embeddings index prior reconnaissance observations to elevate accuracy on subsequent runs.
              </p>
            </div>
            <button
              onClick={() => refetchMemory()}
              className="flex items-center gap-2 px-3.5 py-2 brutal-btn-secondary text-xs font-bold cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Refresh Store
            </button>
          </div>

          {/* Vector Collection Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-[#141A23] border-2 border-black shadow-[4px_4px_0px_#000] p-6 hover:-translate-y-0.5 transition-all">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-xs font-bold text-[#94A3B8] uppercase tracking-wider font-mono">Findings Collection</p>
                  <h3 className="text-3xl font-extrabold text-[#F8FAFC] mt-2 font-mono">
                    {isMemoryLoading ? "..." : memorySummary?.counts?.findings_indexed ?? 0}
                  </h3>
                </div>
                <div className="p-3 bg-[#EF4444] text-white border-2 border-black shadow-[2px_2px_0px_#000]">
                  <ShieldAlert className="w-6 h-6 text-white" />
                </div>
              </div>
              <div className="mt-4 pt-3 border-t-2 border-black text-[11px] text-[#94A3B8]">
                <span>Indexed vulnerability reasoning & evidence vectors</span>
              </div>
            </div>

            <div className="bg-[#141A23] border-2 border-black shadow-[4px_4px_0px_#000] p-6 hover:-translate-y-0.5 transition-all">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-xs font-bold text-[#94A3B8] uppercase tracking-wider font-mono">Features Collection</p>
                  <h3 className="text-3xl font-extrabold text-[#F8FAFC] mt-2 font-mono">
                    {isMemoryLoading ? "..." : memorySummary?.counts?.features_indexed ?? 0}
                  </h3>
                </div>
                <div className="p-3 bg-[#C084FC] text-black border-2 border-black shadow-[2px_2px_0px_#000]">
                  <Layers className="w-6 h-6 text-black" />
                </div>
              </div>
              <div className="mt-4 pt-3 border-t-2 border-black text-[11px] text-[#94A3B8]">
                <span>Semantic capability fingerprints & route patterns</span>
              </div>
            </div>

            <div className="bg-[#141A23] border-2 border-black shadow-[4px_4px_0px_#000] p-6 hover:-translate-y-0.5 transition-all">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-xs font-bold text-[#94A3B8] uppercase tracking-wider font-mono">Routes Collection</p>
                  <h3 className="text-3xl font-extrabold text-[#F8FAFC] mt-2 font-mono">
                    {isMemoryLoading ? "..." : memorySummary?.counts?.routes_indexed ?? 0}
                  </h3>
                </div>
                <div className="p-3 bg-[#38BDF8] text-black border-2 border-black shadow-[2px_2px_0px_#000]">
                  <Compass className="w-6 h-6 text-black" />
                </div>
              </div>
              <div className="mt-4 pt-3 border-t-2 border-black text-[11px] text-[#94A3B8]">
                <span>Discovered URL endpoints & structural DOM summaries</span>
              </div>
            </div>
          </div>

          {/* How Future Missions Use Semantic Memory */}
          <div className="bg-[#141A23] border-2 border-black shadow-[4px_4px_0px_#000] p-6 lg:p-8 space-y-6">
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-[#E2F952] text-black border-2 border-black shadow-[2px_2px_0px_#000]">
                <BrainCircuit className="w-5 h-5 text-black" />
              </div>
              <div>
                <h2 className="text-base font-bold text-[#F8FAFC]">
                  How Future Missions Use <span className="font-editorial italic font-normal text-[#E2F952]">Semantic Memory</span>
                </h2>
                <p className="text-xs text-[#94A3B8]">Cross-mission memory transfers knowledge so each scan is smarter than the last.</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] space-y-2">
                <div className="flex items-center gap-2 text-xs font-bold text-[#38BDF8] font-mono">
                  <Compass className="w-4 h-4" /> 1. Capability Matching
                </div>
                <p className="text-xs text-[#94A3B8] leading-relaxed">
                  When encountering an ambiguous endpoint, the feature extractor queries ChromaDB vectors to find which capabilities similar pages mapped to in previous targets.
                </p>
              </div>

              <div className="p-4 bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] space-y-2">
                <div className="flex items-center gap-2 text-xs font-bold text-[#C084FC] font-mono">
                  <Cpu className="w-4 h-4" /> 2. Few-Shot In-Context Injection
                </div>
                <p className="text-xs text-[#94A3B8] leading-relaxed">
                  During <code className="text-[#F8FAFC] bg-[#141A23] border border-black px-1 py-0.5 font-mono text-[11px]">RUN_ANALYSIS</code>, the orchestrator retrieves the 3 closest past findings and supplies them to Groq LLM as historical evidence context.
                </p>
              </div>

              <div className="p-4 bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] space-y-2">
                <div className="flex items-center gap-2 text-xs font-bold text-[#10B981] font-mono">
                  <Zap className="w-4 h-4" /> 3. High-Yield Crawl Elevation
                </div>
                <p className="text-xs text-[#94A3B8] leading-relaxed">
                  The risk scorer boosts parameters and routes that share vector patterns with previously confirmed vulnerabilities, guiding the crawler toward fertile attack surfaces.
                </p>
              </div>
            </div>
          </div>

          {/* Interactive Semantic Search Bar */}
          <div className="bg-[#141A23] border-2 border-black shadow-[4px_4px_0px_#000] p-6 lg:p-8 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-bold text-[#F8FAFC] flex items-center gap-2">
                  <Search className="w-4 h-4 text-[#E2F952]" /> Query Vector Index
                </h2>
                <p className="text-xs text-[#94A3B8]">Test semantic similarity search across vector collections in real-time.</p>
              </div>

              {/* Collection Filter */}
              <div className="flex bg-[#0E1217] p-1 border-2 border-black shadow-[1.5px_1.5px_0px_#000] self-start sm:self-auto gap-1">
                {["findings", "features", "routes"].map((col) => (
                  <button
                    key={col}
                    type="button"
                    onClick={() => {
                      setCollection(col);
                      setSearchResults(null);
                    }}
                    className={`px-3 py-1.5 text-xs font-mono font-bold capitalize transition-all cursor-pointer ${
                      collection === col
                        ? "bg-[#E2F952] text-black shadow-[1px_1px_0px_#000]"
                        : "text-[#94A3B8] hover:text-[#F8FAFC]"
                    }`}
                  >
                    {col}
                  </button>
                ))}
              </div>
            </div>

            <form onSubmit={handleSearch} className="flex gap-3">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-[#94A3B8] absolute left-4 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder={`Search ${collection} by meaning (e.g. "missing csrf token", "admin authentication")...`}
                  className="w-full bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] pl-11 pr-4 py-3 text-xs text-[#F8FAFC] placeholder-[#64748B] focus:border-black outline-none font-mono"
                />
              </div>
              <button
                type="submit"
                disabled={searching}
                className="brutal-btn-primary px-6 py-3 text-xs font-bold flex items-center gap-2 shrink-0 cursor-pointer disabled:opacity-50"
              >
                {searching ? (
                  <RefreshCw className="w-4 h-4 animate-spin text-black" />
                ) : (
                  <Search className="w-4 h-4 text-black" />
                )}
                Vector Search
              </button>
            </form>

            {/* Live Search Results */}
            {searchResults !== null && (
              <div className="space-y-3 pt-4 border-t-2 border-black">
                <div className="flex justify-between items-center">
                  <span className="text-xs font-mono font-bold text-[#94A3B8]">
                    Matched {searchResults.length} {searchResults.length === 1 ? "document" : "documents"} for "{searchQuery}"
                  </span>
                  <button
                    type="button"
                    onClick={() => setSearchResults(null)}
                    className="text-xs text-[#EF4444] hover:underline font-bold font-mono cursor-pointer"
                  >
                    Clear Results
                  </button>
                </div>

                {searchResults.length === 0 ? (
                  <div className="p-8 text-center text-xs text-[#94A3B8] bg-[#0E1217] border-2 border-black">
                    No vector matches found with current query threshold.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-3">
                    {searchResults.map((res, i) => (
                      <div
                        key={i}
                        className="p-4 bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] hover:shadow-[3px_3px_0px_#000] transition-all space-y-2"
                      >
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-bold text-[#F8FAFC] bg-[#141A23] border border-black px-2 py-0.5">
                              {res.document_id}
                            </span>
                            {res.metadata?.severity && (
                              <span
                                className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 border border-black shadow-[1px_1px_0px_#000] ${getSeverityStyle(
                                  res.metadata.severity
                                )}`}
                              >
                                {res.metadata.severity}
                              </span>
                            )}
                            {res.metadata?.feature && (
                              <span className="text-[10px] font-mono text-[#CBD5E1] bg-[#141A23] px-2 py-0.5 border border-black">
                                {res.metadata.feature}
                              </span>
                            )}
                          </div>
                          <span className="text-xs font-mono font-bold text-[#10B981] bg-[#10B981]/20 px-2 py-0.5 border border-black shadow-[1px_1px_0px_#000]">
                            {res.similarity_score}% Match
                          </span>
                        </div>
                        <p className="text-xs font-mono text-[#CBD5E1] whitespace-pre-wrap leading-relaxed line-clamp-3">
                          {res.document}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Stored Historical Findings Preview */}
          <div className="bg-[#141A23] border-2 border-black shadow-[4px_4px_0px_#000] p-6 lg:p-8 space-y-6">
            <div>
              <h2 className="text-base font-bold text-[#F8FAFC] flex items-center gap-2">
                <Database className="w-4 h-4 text-[#E2F952]" /> Stored Semantic Knowledge Base
              </h2>
              <p className="text-xs text-[#94A3B8]">Observations currently embedded and available to subsequent analysis workflows.</p>
            </div>

            {memorySummary?.recent_stored_findings?.length === 0 ? (
              <div className="p-8 text-center text-xs text-[#94A3B8] bg-[#0E1217] border-2 border-black">
                No findings indexed yet. Run your first mission to populate semantic memory!
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="bg-[#0E1217] border-b-2 border-black text-[#94A3B8] font-bold uppercase tracking-wider text-[10px]">
                      <th className="p-3">ID</th>
                      <th className="p-3">Title</th>
                      <th className="p-3">Category</th>
                      <th className="p-3">Feature Context</th>
                      <th className="p-3">Severity</th>
                      <th className="p-3">Embedded Excerpt</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-black/60">
                    {memorySummary?.recent_stored_findings?.map((f: any, idx: number) => (
                      <tr key={idx} className="hover:bg-[#18202C] transition-colors">
                        <td className="p-3 font-mono text-[#38BDF8] font-bold text-[11px]">{f.id}</td>
                        <td className="p-3 font-bold text-[#F8FAFC] max-w-[200px] truncate" title={f.title}>
                          {f.title}
                        </td>
                        <td className="p-3 text-[#94A3B8]">{f.type}</td>
                        <td className="p-3 text-[#94A3B8]">{f.feature}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 border border-black shadow-[1px_1px_0px_#000] text-[10px] font-mono font-bold uppercase ${getSeverityStyle(f.severity)}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="p-3 text-[#94A3B8] max-w-[320px] truncate font-mono text-[11px]" title={f.snippet}>
                          {f.snippet}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Side Sliding Drawer Overlay */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/80 z-50 flex justify-end animate-fadeIn">
          {/* Backdrop closer */}
          <div className="absolute inset-0" onClick={() => setSelectedFinding(null)}></div>

          {/* Drawer Body */}
          <div className="w-full max-w-xl bg-[#141A23] border-l-2 border-black p-8 z-10 overflow-y-auto space-y-6 flex flex-col justify-between shadow-2xl relative animate-slideLeft">
            <button
              onClick={() => setSelectedFinding(null)}
              className="absolute top-6 right-6 p-2 bg-[#0E1217] hover:bg-[#1C2533] border-2 border-black shadow-[2px_2px_0px_#000] text-[#94A3B8] hover:text-[#F8FAFC] transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="space-y-6">
              {/* Finding Title & Severity */}
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="font-mono text-xs font-bold text-[#E2F952]">{selectedFinding.finding_id}</span>
                  <span className={`px-2 py-0.5 text-[10px] font-mono font-extrabold uppercase tracking-wide border border-black shadow-[1px_1px_0px_#000] ${getSeverityStyle(selectedFinding.severity)}`}>
                    {selectedFinding.severity}
                  </span>
                  <span className="text-xs text-[#94A3B8] font-mono">
                    {Math.round((selectedFinding.confidence > 1 ? selectedFinding.confidence : selectedFinding.confidence * 100))}% Confidence
                  </span>
                </div>
                <h2 className="text-lg font-bold text-[#F8FAFC]">{selectedFinding.title}</h2>
              </div>

              {/* Description */}
              <div className="space-y-2">
                <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider font-mono">Detailed Observation</span>
                <p className="text-xs text-[#CBD5E1] leading-relaxed bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] p-4 font-sans">
                  {selectedFinding.description}
                </p>
              </div>

              {/* Explainable Security Reasoning */}
              {selectedFinding.reasoning && (
                <div className="space-y-2">
                  <span className="text-[10px] font-bold text-[#C084FC] uppercase tracking-wider flex items-center gap-1.5 font-mono">
                    <Sparkles className="w-3.5 h-3.5" /> Explainable Security Reasoning
                  </span>
                  <div className="p-4 bg-[#181524] border-2 border-black shadow-[2px_2px_0px_#000] text-[#DDD6FE]">
                    <p className="text-xs leading-relaxed font-editorial italic">{selectedFinding.reasoning}</p>
                  </div>
                </div>
              )}

              {/* Remediation Guidance */}
              {selectedFinding.recommendation && (
                <div className="space-y-2">
                  <span className="text-[10px] font-bold text-[#10B981] uppercase tracking-wider flex items-center gap-1.5 font-mono">
                    <ClipboardCheck className="w-3.5 h-3.5" /> Recommended Remediation
                  </span>
                  <div className="p-4 bg-[#0A1A14] border-2 border-black shadow-[2px_2px_0px_#000] text-[#A7F3D0]">
                    <p className="text-xs leading-relaxed font-sans">{selectedFinding.recommendation}</p>
                  </div>
                </div>
              )}

              {/* Evidence Log */}
              {selectedFinding.evidence && selectedFinding.evidence.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider font-mono">Concrete Evidence Log</span>
                  <div className="bg-[#0E1217] border-2 border-black shadow-[2px_2px_0px_#000] p-4 space-y-1.5 max-h-48 overflow-y-auto font-mono text-[11px] text-[#38BDF8]">
                    {selectedFinding.evidence.map((ev, i) => (
                      <div key={i} className="flex gap-2">
                        <span className="text-[#94A3B8] select-none font-bold">{i + 1}.</span>
                        <span className="break-all">{ev}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Bottom Actions */}
            <div className="pt-6 border-t-2 border-black flex items-center justify-between">
              <span className="text-xs text-[#94A3B8]">Originating Mission: <span className="text-[#E2F952] font-mono font-bold">{selectedFinding.mission}</span></span>
              <Link
                to={`/mission/${selectedFinding.mission}`}
                className="brutal-btn-primary px-4 py-2 text-xs font-bold flex items-center gap-1.5 cursor-pointer"
              >
                <span>Inspect Mission</span>
                <ExternalLink className="w-3.5 h-3.5 text-black" />
              </Link>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
