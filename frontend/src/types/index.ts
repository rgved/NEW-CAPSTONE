export interface Mission {
  mission_id: string;
  target: string;
  status: "running" | "completed" | "failed";
  created_at: string;
  findings_count: number;
}

export interface ReconSummary {
  routes: number;
  forms: number;
  inputs: number;
  buttons: number;
  scripts: number;
  links: number;
  meta_tags: number;
  is_spa?: boolean;
}

export interface FeatureItem {
  name: string;
  confidence: number;
}

export interface TokenReduction {
  original_tokens: number;
  reduced_tokens: number;
  reduction_percentage: number;
}

export interface PrioritizedEndpoint {
  url: string;
  risk_score: number;
  priority: "critical" | "high" | "medium" | "low";
  exposure: number;
  sensitivity: number;
  reachability: number;
  reason: string;
}

export interface Finding {
  finding_id: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  // Second opinion from the Nuclei-trained TF-IDF + linear SVM severity model.
  model_severity?: string | null;
  confidence: number;
  evidence: string[];
  description: string;
  reasoning?: string;
  mission?: string;
  date?: string;
  recommendation?: string;
}

export interface MissionDetail {
  mission_id: string;
  target_url: string;
  status: "running" | "completed" | "failed";
  runtime: string;
  generated_at: string;
  recon_summary: ReconSummary;
  features: FeatureItem[];
  token_reduction?: TokenReduction;
  findings: Finding[];
  prioritized_attack_surface?: PrioritizedEndpoint[];
  report_id: string | null;
}

export interface TimelineTask {
  task: string;
  status: "pending" | "running" | "completed" | "failed";
  timestamp: string;
}

export interface DashboardStats {
  total_missions: number;
  assets_scanned?: number;
  total_findings: number;
  critical_findings?: number;
  high_findings?: number;
  security_score?: number;
  avg_token_reduction?: number;
  features_identified: number;
}

export interface DashboardData {
  stats: DashboardStats;
  recent_missions: {
    mission_id: string;
    target: string;
    status: "running" | "completed" | "failed";
    date: string;
    findings: number;
  }[];
  findings_severity: {
    severity: string;
    count: number;
  }[];
  findings_breakdown_full?: {
    severity: string;
    count: number;
  }[];
  feature_distribution: {
    name: string;
    value: number;
  }[];
}

export interface ReportItem {
  report_id: string;
  mission_id: string;
  target: string;
  generated_at: string;
}

export interface ReportFinding {
  finding_id: string;
  title: string;
  category: string;
  severity: "informational" | "low" | "medium" | "high";
  confidence: number;
  evidence: string[];
  description: string;
  reasoning?: string;
}

export interface SecurityReport {
  report_id: string;
  mission_id: string;
  target_url: string;
  generated_at: string;
  executive_summary: string;
  coverage_summary: string;
  severity_breakdown: Record<string, number>;
  findings: ReportFinding[];
  recommendations: string[];
  statistics: Record<string, any>;
}

export interface MetricsData {
  total_missions: number;
  total_findings: number;
  avg_runtime: number;
  avg_token_reduction: number;
  token_reduction_by_mission: {
    mission_id: string;
    reduction: number;
  }[];
  findings_by_severity: {
    severity: string;
    count: number;
  }[];
  feature_distribution: {
    name: string;
    count: number;
  }[];
  mission_runtime_trend: {
    mission_id: string;
    runtime: number;
  }[];
}
