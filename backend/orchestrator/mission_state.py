"""
backend/orchestrator/mission_state.py

Mission state tracked by the orchestrator (updated Phase 5).
"""
from typing import Literal, Optional

from pydantic import BaseModel, Field

from backend.models.coverage_state import CoverageState


class MissionState(BaseModel):
    mission_id: str
    target: str
    status: Literal["running", "completed", "failed"] = "running"
    coverage: CoverageState = Field(default_factory=CoverageState)
    features_extracted: bool = False
    efficient_fetch_completed: bool = False
    analysis_completed: bool = False
    severity_model_completed: bool = False
    report_generated: bool = False
    current_task_id: Optional[str] = None
