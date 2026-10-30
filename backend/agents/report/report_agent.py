"""
backend/agents/report/report_agent.py

Phase 7 Report Agent.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.models.feature import Feature
from backend.models.finding import Finding
from backend.models.route import Route
from backend.models.security_report import ReportFinding, SecurityReport
from backend.models.task import Task
from backend.models.worker_response import WorkerError, WorkerResponse
from backend.services.logger import get_logger

logger = get_logger(__name__)

_WORKER_NAME = "report"
_REPORT_ID_PREFIX = "REPORT-"


class ReportAgent:
    def __init__(self) -> None:
        self._report_counter = 0

    async def execute(self, task: Task) -> WorkerResponse:
        if task.task_id is None:
            raise ValueError("Task must have task_id before report generation")

        logger.info("ReportAgent starting - task_id=%s target=%s", task.task_id, task.target)

        try:
            mission_id, target_url = self._parse_mission(task.context)
            findings = self._parse_findings(task.context.get("findings"))
            features = self._parse_features(task.context.get("features"))
            routes = self._parse_routes(task.context.get("routes"))
            recon_result = task.context.get("recon_result")
            report = self.build_report(mission_id, target_url, findings, features, routes, recon_result=recon_result)
        except ValueError as exc:
            return self._failure_response(task.task_id, "REPORT_GENERATION_FAILED", str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected report failure - task_id=%s", task.task_id)
            return self._failure_response(task.task_id, "REPORT_FAILURE", self._safe_message(exc))

        logger.info("ReportAgent complete - task_id=%s report_id=%s", task.task_id, report.report_id)
        return WorkerResponse(
            status="success",
            worker=_WORKER_NAME,
            task_id=task.task_id,
            data={"report_id": report.report_id, "report": report.model_dump()},
            new_findings=[],
            errors=[],
        )

    def build_report(
        self,
        mission_id: str,
        target_url: str,
        findings: list[Finding],
        features: list[Feature],
        routes: list[Route],
        recon_result: dict[str, Any] | None = None,
    ) -> SecurityReport:
        self._report_counter += 1
        report_id = f"{_REPORT_ID_PREFIX}{self._report_counter:03d}"
        generated_at = datetime.now(timezone.utc)
        severity_breakdown = self._severity_breakdown(findings)
        severity_order = {"high": 3, "medium": 2, "low": 1, "informational": 0}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get((f.severity or "").lower(), 0),
            reverse=True,
        )
        report_findings = [
            ReportFinding(
                finding_id=finding.finding_id or "",
                title=finding.title,
                category=finding.type,
                severity=finding.severity,
                confidence=finding.security_confidence,
                evidence=finding.evidence,
                description=finding.description,
                reasoning=finding.reasoning,
                model_severity=finding.model_severity,
            )
            for finding in sorted_findings
        ]

        report = SecurityReport(
            report_id=report_id,
            mission_id=mission_id,
            target_url=target_url,
            generated_at=generated_at,
            executive_summary=self._build_executive_summary(findings, features),
            coverage_summary=self._build_coverage_summary(routes, features, findings),
            severity_breakdown=severity_breakdown,
            findings=report_findings,
            recommendations=self._build_recommendations(findings, features),
            statistics=self._build_statistics(routes, features, findings, recon_result=recon_result),
        )
        return report

    def _build_executive_summary(self, findings: list[Finding], features: list[Feature]) -> str:
        feature_count = len(features)
        finding_count = len(findings)
        most_severe = self._most_severe_finding(findings)
        summary_lines = [
            "The target application was analyzed using the agentic reconnaissance platform.",
            f"{feature_count} feature{'s were' if feature_count != 1 else ' was'} identified.",
            f"{finding_count} finding{'s were' if finding_count != 1 else ' was'} generated.",
        ]
        if most_severe is not None:
            summary_lines.append(f"Most severe finding: {most_severe.title}.")
        return " ".join(summary_lines)

    def _build_coverage_summary(self, routes: list[Route], features: list[Feature], findings: list[Finding]) -> str:
        return "\n".join(
            [
                f"Routes Discovered: {len(routes)}",
                f"Features Identified: {len(features)}",
                f"Findings Generated: {len(findings)}",
            ]
        )

    def _build_recommendations(self, findings: list[Finding], features: list[Feature]) -> list[str]:
        recommendations: list[str] = []
        finding_types = {finding.type for finding in findings}

        if "missing_csrf" in finding_types:
            recommendations.append("Implement anti-CSRF tokens on state-changing forms.")
        if "weak_authentication" in finding_types:
            recommendations.append("Strengthen authentication controls and review login hardening.")
        if "missing_security_headers" in finding_types:
            recommendations.append("Add the missing baseline security headers.")
        if "admin_surface" in finding_types:
            recommendations.append("Restrict administrative functionality with strong authorization checks.")
        if "file_upload_risk" in finding_types:
            recommendations.append("Validate file uploads server-side and restrict allowed file types.")
        if "vulnerable_dependency" in finding_types:
            recommendations.append("Upgrade outdated client-side libraries to modern patched releases.")
        if "missing_subresource_integrity" in finding_types:
            recommendations.append("Add integrity and crossorigin attributes to external third-party CDN scripts.")
        if "verbose_error_leak" in finding_types:
            recommendations.append("Disable verbose debugging and configure generic error pages in production.")
        if "sensitive_input" in finding_types:
            recommendations.append("Sanitize and encode all user-controlled inputs before reflection.")
        if not recommendations and features:
            recommendations.append("Review the discovered features for security-sensitive input handling.")
        if not recommendations:
            recommendations.append("No direct remediation guidance was generated from the current findings.")
        return recommendations

    def _build_statistics(
        self,
        routes: list[Route],
        features: list[Feature],
        findings: list[Finding],
        recon_result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        stats: dict[str, Any] = {
            "routes_discovered": len(routes),
            "features_identified": len(features),
            "findings_generated": len(findings),
            "severity_breakdown": self._severity_breakdown(findings),
        }
        if recon_result and isinstance(recon_result, dict):
            stats["forms_count"] = len(recon_result.get("forms", []))
            stats["inputs_count"] = len(recon_result.get("inputs", []))
            stats["buttons_count"] = len(recon_result.get("buttons", []))
            stats["scripts_count"] = len(recon_result.get("scripts", []))
            stats["links_count"] = len(recon_result.get("links", []))
            stats["meta_tags_count"] = len(recon_result.get("meta_tags", []))
            stats["comments_count"] = len(recon_result.get("comments", []))
            stats["is_spa"] = bool(recon_result.get("is_spa", False))
        return stats

    def _severity_breakdown(self, findings: list[Finding]) -> dict[str, int]:
        breakdown = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for finding in findings:
            key = finding.severity.capitalize()
            if key not in breakdown:
                key = "Informational"
            breakdown[key] += 1
        return breakdown

    def _most_severe_finding(self, findings: list[Finding]) -> Finding | None:
        order = {"high": 3, "medium": 2, "low": 1, "informational": 0}
        if not findings:
            return None
        return sorted(findings, key=lambda finding: order.get(finding.severity, 0), reverse=True)[0]

    def _parse_mission(self, context: dict[str, Any]) -> tuple[str, str]:
        mission_id = context.get("mission_id")
        target_url = context.get("target_url")
        if not isinstance(mission_id, str) or not mission_id.strip():
            raise ValueError("Task context must include mission_id")
        if not isinstance(target_url, str) or not target_url.strip():
            raise ValueError("Task context must include target_url")
        return mission_id, target_url

    def _parse_findings(self, value: Any) -> list[Finding]:
        if not isinstance(value, list):
            return []
        findings: list[Finding] = []
        for item in value:
            if isinstance(item, dict):
                findings.append(Finding.model_validate(item))
            elif hasattr(item, "model_dump"):
                findings.append(Finding.model_validate(item.model_dump()))
        return findings

    def _parse_features(self, value: Any) -> list[Feature]:
        if not isinstance(value, list):
            return []
        features: list[Feature] = []
        for item in value:
            if isinstance(item, dict):
                features.append(Feature.model_validate(item))
            elif hasattr(item, "model_dump"):
                features.append(Feature.model_validate(item.model_dump()))
        return features

    def _parse_routes(self, value: Any) -> list[Route]:
        if not isinstance(value, list):
            return []
        routes: list[Route] = []
        for item in value:
            if isinstance(item, dict):
                routes.append(Route.model_validate(item))
            elif hasattr(item, "model_dump"):
                routes.append(Route.model_validate(item.model_dump()))
        return routes

    def _failure_response(self, task_id: str, error_type: str, message: str) -> WorkerResponse:
        return WorkerResponse(
            status="failure",
            worker=_WORKER_NAME,
            task_id=task_id,
            data={},
            new_findings=[],
            errors=[WorkerError(error_type=error_type, message=message)],
        )

    def _safe_message(self, exc: Exception) -> str:
        message = str(exc).strip()
        return message or "Report generation failed"
