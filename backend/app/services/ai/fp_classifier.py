"""False-positive classifier using Isolation Forest (classical ML).

Why classical ML, not deep learning? FP reduction on tabular finding features
(CVSS, EPSS, scanner confidence, context flags, historical analyst verdicts) is
an outlier-detection problem that Isolation Forest / LOF solve cheaply,
interpretable, and without labelled breach data or GPUs. The model's decisions
are logged for auditability — unlike a black-box transformer.

Training: bootstrap with rule-based heuristics + analyst feedback (active
learning). The model artifact lives in ml/registry/.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import numpy as np
from app.core.config import settings
from app.core.logging import get_logger
from app.models.finding import Finding

log = get_logger(__name__)

# Feature vector: [cvss, scanner_confidence, has_cwe, has_cvss, severity_rank, is_info]
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class FPResult:
    fp_score: float  # 0..1, higher = more likely FP
    label: str  # likely_tp | uncertain | likely_fp
    method: str  # isoforest | heuristic


def extract_features(finding: Finding) -> np.ndarray:
    return np.array([
        float(finding.cvss or 0.0) / 10.0,
        float(finding.scanner_confidence or 0.5),
        1.0 if finding.cwe else 0.0,
        1.0 if finding.cvss else 0.0,
        SEVERITY_RANK.get(finding.severity.value if hasattr(finding.severity, "value") else finding.severity, 0) / 4.0,
        1.0 if (finding.severity.value if hasattr(finding.severity, "value") else finding.severity) == "info" else 0.0,
    ])


_model = None


def _load_model():
    global _model
    if _model is not None:
        return _model
    path = settings.fp_model_path
    if os.path.exists(path):
        try:
            import joblib

            _model = joblib.load(path)
            log.info("fp_classifier.model_loaded", path=path)
        except Exception as e:  # pragma: no cover
            log.warning("fp_classifier.load_failed", error=str(e))
            _model = False  # sentinel: tried and failed
    else:
        log.info("fp_classifier.no_model_using_heuristic")
        _model = False
    return _model


def classify(finding: Finding) -> FPResult:
    """Return an FP score + label for a finding."""
    model = _load_model()
    feats = extract_features(finding).reshape(1, -1)

    if model and model is not False:
        # Isolation Forest: -1 = anomaly (likely FP), 1 = normal (likely TP)
        # decision_function: lower = more anomalous (range ~[-0.5, 0.5])
        try:
            raw = float(model.decision_function(feats)[0])
            # map [-0.5, 0.5] -> [1.0, 0.0] fp_score (more anomalous => higher fp_score)
            fp_score = max(0.0, min(1.0, 0.5 - raw))
            pred = int(model.predict(feats)[0])
            label = "likely_fp" if pred == -1 and fp_score > 0.6 else ("uncertain" if fp_score > 0.35 else "likely_tp")
            return FPResult(fp_score=fp_score, label=label, method="isoforest")
        except Exception as e:  # pragma: no cover
            log.warning("fp_classifier.predict_failed", error=str(e))

    # Heuristic fallback (no trained model)
    return _heuristic(finding)


def _heuristic(finding: Finding) -> FPResult:
    """Rule-based FP estimate when no model is trained yet."""
    score = 0.0
    sev = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
    if sev == "info":
        score += 0.4
    if not finding.cwe:
        score += 0.15
    if not finding.cvss:
        score += 0.1
    if (finding.scanner_confidence or 0.5) < 0.4:
        score += 0.2
    score = min(score, 0.95)
    label = "likely_fp" if score > 0.6 else ("uncertain" if score > 0.35 else "likely_tp")
    return FPResult(fp_score=score, label=label, method="heuristic")
