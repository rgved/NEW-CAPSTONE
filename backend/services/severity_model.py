"""
backend/services/severity_model.py

ML severity model service (TF-IDF + linear SVM trained on Nuclei templates).

Loads the saved ``nuclei_model.pkl`` artifact produced by the capstone ML
experiment. The pickle is a dict with keys: ``vectorizer`` (fitted
TfidfVectorizer), ``model`` (fitted LinearSVC) and ``labels`` (the five
ordered labels: info/low/medium/high/critical).

The artifact does NOT embed the text-cleaning function, so the exact
training-time cleaning is replicated here (from the experiment notebook)::

    text = title + ' . ' + description
    text = re.sub(r'CVE-\\d{4}-\\d+', '', text, flags=re.I)
    text = re.sub(r'\\b(critical|high|medium|low|informational|info|severity|cvss)\\b',
                  ' ', text, flags=re.I)

Honesty note: the model was trained to predict Nuclei template authors'
severity ratings. On this scanner's LLM-written findings it is an
unvalidated second opinion, not proof of exploitability.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional

from backend.services.logger import get_logger

logger = get_logger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_SEV_WORDS_RE = re.compile(
    r"\b(critical|high|medium|low|informational|info|severity|cvss)\b", re.I
)

# Map the model's Nuclei-style labels onto the app's severity vocabulary.
_LABEL_MAP = {
    "info": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

_DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "ml" / "nuclei_model.pkl"


class SeverityModelService:
    """Lazy-loading wrapper around the saved Nuclei severity model."""

    def __init__(self, model_path: Optional[Path] = None) -> None:
        env_path = os.environ.get("SEVERITY_MODEL_PATH")
        self._model_path = Path(env_path) if env_path else (model_path or _DEFAULT_MODEL_PATH)
        self._artifact: Optional[dict[str, Any]] = None
        self._load_error: Optional[str] = None
        self._loaded = False

    @property
    def model_path(self) -> Path:
        return self._model_path

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._model_path.is_file():
            self._load_error = f"model file not found: {self._model_path}"
            logger.warning("Severity model unavailable - %s", self._load_error)
            return
        try:
            import pickle

            with self._model_path.open("rb") as fh:
                artifact = pickle.load(fh)
            for key in ("vectorizer", "model", "labels"):
                if key not in artifact:
                    raise ValueError(f"model artifact missing key: {key}")
            self._artifact = artifact
            logger.info(
                "Severity model loaded - path=%s labels=%s",
                self._model_path,
                artifact["labels"],
            )
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"{type(exc).__name__}: {exc}"
            logger.exception("Severity model failed to load - path=%s", self._model_path)

    @staticmethod
    def clean_finding(title: str, description: str) -> str:
        """Exact training-time cleaning for model inputs."""
        text = f"{title} . {description}"
        text = _CVE_RE.sub("", text)
        return _SEV_WORDS_RE.sub(" ", text)

    @property
    def available(self) -> bool:
        self._load()
        return self._artifact is not None

    @property
    def load_error(self) -> Optional[str]:
        self._load()
        return self._load_error

    def predict(self, title: str, description: str = "") -> Optional[dict[str, str]]:
        """Return {'model_label', 'model_severity'} for one finding, or None.

        ``model_label`` is the raw Nuclei label; ``model_severity`` is the
        same verdict in the app's severity vocabulary.
        """
        self._load()
        if self._artifact is None:
            return None
        text = self.clean_finding(title or "", description or "")
        features = self._artifact["vectorizer"].transform([text])
        class_id = int(self._artifact["model"].predict(features)[0])
        raw_label = str(self._artifact["labels"][class_id])
        return {
            "model_label": raw_label,
            "model_severity": _LABEL_MAP.get(raw_label, raw_label),
        }


_SERVICE: Optional[SeverityModelService] = None


def get_severity_model() -> SeverityModelService:
    """Process-wide shared service instance (model loads once)."""
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = SeverityModelService()
    return _SERVICE
