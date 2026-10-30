"""
backend/orchestrator/task_dispatcher.py

Phase 7 task dispatcher.

Supported actions
-----------------
RUN_RECON           -> ReconAgent
EXTRACT_FEATURES    -> FeatureExtractionAgent
RUN_EFFICIENT_FETCH -> EfficientFetchWorker
RUN_ANALYSIS        -> AnalysisAgent
GENERATE_REPORT     -> ReportAgent

Design note
-----------
FeatureExtractionAgent depends on ``openai`` which may not be installed in
all environments (e.g. during unit testing). Its import is deferred so that
importing ``TaskDispatcher`` itself does not immediately trigger that
dependency. Tests can inject stubs via the constructor parameters without
ever loading the real agent.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from backend.agents.efficient_fetch.efficient_fetch_worker import EfficientFetchWorker
from backend.agents.recon.recon_agent import ReconAgent
from backend.models.task import Task
from backend.models.worker_response import WorkerResponse
from backend.services.logger import get_logger

if TYPE_CHECKING:
    from backend.agents.analysis.analysis_agent import AnalysisAgent
    from backend.agents.feature_extraction.feature_extraction_agent import FeatureExtractionAgent
    from backend.agents.report.report_agent import ReportAgent

logger = get_logger(__name__)


class TaskDispatcher:
    def __init__(
        self,
        recon_agent: ReconAgent | None = None,
        feature_extraction_agent: FeatureExtractionAgent | None = None,
        efficient_fetch_worker: EfficientFetchWorker | None = None,
        analysis_agent: AnalysisAgent | None = None,
        report_agent: ReportAgent | None = None,
        severity_model_agent=None,
    ) -> None:
        self._recon_agent: ReconAgent = recon_agent or ReconAgent()

        if feature_extraction_agent is not None:
            self._feature_extraction_agent = feature_extraction_agent
        else:
            from backend.agents.feature_extraction.feature_extraction_agent import FeatureExtractionAgent as _FEA

            self._feature_extraction_agent = _FEA()

        self._efficient_fetch_worker: EfficientFetchWorker = efficient_fetch_worker or EfficientFetchWorker()
        self._analysis_agent = analysis_agent
        self._report_agent = report_agent
        self._severity_model_agent = severity_model_agent

    async def dispatch(self, task: Task) -> WorkerResponse:
        if task.task_id is None:
            raise ValueError("Task must have task_id before dispatch")

        logger.info("Dispatching task %s (%s)", task.task_id, task.action)

        if task.action == "RUN_RECON":
            return await self._recon_agent.execute(task)

        if task.action == "EXTRACT_FEATURES":
            return await self._feature_extraction_agent.execute(task)

        if task.action == "RUN_EFFICIENT_FETCH":
            return await self._efficient_fetch_worker.execute(task)

        if task.action == "RUN_ANALYSIS":
            return await self._get_analysis_agent().execute(task)

        if task.action == "RUN_SEVERITY_MODEL":
            return await self._get_severity_model_agent().execute(task)

        if task.action == "GENERATE_REPORT":
            return await self._get_report_agent().execute(task)

        return WorkerResponse(
            status="failure",
            worker="dispatcher",
            task_id=task.task_id,
            data={},
            new_findings=[],
            errors=[
                {
                    "error_type": "UNSUPPORTED_ACTION",
                    "message": f"Unsupported action: {task.action}",
                }
            ],
        )

    def _get_analysis_agent(self):
        if self._analysis_agent is not None:
            return self._analysis_agent

        from backend.agents.analysis.analysis_agent import AnalysisAgent as _AA

        self._analysis_agent = _AA()
        return self._analysis_agent

    def _get_severity_model_agent(self):
        if self._severity_model_agent is not None:
            return self._severity_model_agent

        from backend.agents.severity_model.severity_model_agent import SeverityModelAgent as _SMA

        self._severity_model_agent = _SMA()
        return self._severity_model_agent

    def _get_report_agent(self):
        if self._report_agent is not None:
            return self._report_agent

        from backend.agents.report.report_agent import ReportAgent as _RA

        self._report_agent = _RA()
        return self._report_agent
