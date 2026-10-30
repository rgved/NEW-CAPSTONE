"""
backend/models/security_report.py

Pydantic model for a Phase 7 security report.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from backend.models.finding import FindingSeverity


class ReportFinding(BaseModel):
    finding_id: str
    title: str
    category: str
    severity: FindingSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    description: str = ""
    reasoning: str = ""
    model_severity: Optional[str] = None


class SecurityReport(BaseModel):
    report_id: Optional[str] = None
    mission_id: str
    target_url: str
    generated_at: datetime
    executive_summary: str
    coverage_summary: str
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    findings: list[ReportFinding] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    statistics: dict[str, Any] = Field(default_factory=dict)
