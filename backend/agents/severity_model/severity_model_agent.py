"""
backend/agents/severity_model/severity_model_agent.py

ML Severity Model agent.

Takes the findings produced by the analysis stage, sends each finding's
title + description through the saved Nuclei-trained TF-IDF + linear SVM,
and returns the model's severity verdict per finding. The verdict is stored
as an additional, clearly labelled second opinion in ``model_severity``;
it never overwrites the LLM's severity.
"""
from __future__ import annotations

from typing import Any

from backend.models.task import Task
from backend.models.worker_response import WorkerResponse
from backend.services.logger import get_logger
from backend.services.severity_model import get_severity_model

logger = get_logger(__name__)

_WORKER_NAME = "severity_model"


class SeverityModelAgent:
    async def execute(self, task: Task) -> WorkerResponse:
        if task.task_id is None:
            raise ValueError("Task must have task_id before severity-model execution")

        findings = task.context.get("findings") or []
        logger.info(
            "SeverityModelAgent starting - task_id=%s findings=%d",
            task.task_id,
            len(findings),
        )

        model = get_severity_model()
        if not model.available:
            # Honest degradation: succeed with model_available=False so the
            # mission continues and the UI shows the model as unavailable
            # instead of inventing severities.
            logger.warning("Severity model unavailable - %s", model.load_error)
            return WorkerResponse(
                status="success",
                worker=_WORKER_NAME,
                task_id=task.task_id,
                data={
                    "model_available": False,
                    "reason": model.load_error or "unknown",
                    "scored_findings": [],
                },
                new_findings=[],
                errors=[],
            )

        scored: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            verdict = model.predict(
                title=str(finding.get("title", "")),
                description=str(finding.get("description", "")),
            )
            if verdict is None:
                continue
            scored.append(
                {
                    "finding_id": finding.get("finding_id"),
                    "title": finding.get("title", ""),
                    **verdict,
                }
            )

        logger.info(
            "SeverityModelAgent complete - task_id=%s scored=%d",
            task.task_id,
            len(scored),
        )
        return WorkerResponse(
            status="success",
            worker=_WORKER_NAME,
            task_id=task.task_id,
            data={"model_available": True, "scored_findings": scored},
            new_findings=[],
            errors=[],
        )
