"""
ml/anomaly_engine.py

Implements the baseline ML pipeline using Isolation Forest.

Why Isolation Forest over statistical thresholds (z-score, IQR):
- Traffic patterns are non-Gaussian and highly seasonal (business hours peaks)
- Isolation Forest makes no distributional assumptions — it isolates anomalies
  by partitioning feature space, naturally handling multi-modal distributions
- It scales to high-dimensional feature spaces (API latency + error rate + 
  request rate + bytes transferred) without manual threshold tuning per feature
- Contamination parameter gives security teams a direct knob to control
  sensitivity vs false positive rate

Limitation: The model requires periodic retraining (see train_baseline) as
normal traffic patterns shift. Stale baselines produce alert fatigue.
"""

import logging
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.core.config import get_settings

logger = logging.getLogger(__name__)

MODEL_DIR = Path("./models")
MODEL_DIR.mkdir(exist_ok=True)


class AnomalyDetector:
    """
    Trains and serves an Isolation Forest anomaly detector.

    State held by this class:
    - _model: The trained IsolationForest instance
    - _scaler: StandardScaler fit on training data (must scale inference data identically)
    - _feature_columns: Feature ordering — must match between training and inference
    - _trained_at: Timestamp for model staleness tracking
    """

    FEATURE_COLUMNS = [
        "request_count",
        "error_rate",
        "avg_latency_ms",
        "bytes_per_request",
        "unique_endpoints",
        "p99_latency_ms",
    ]

    def __init__(self) -> None:
        settings = get_settings()
        self._contamination = settings.isolation_forest_contamination
        self._n_estimators = settings.isolation_forest_n_estimators
        self._score_threshold = settings.anomaly_score_threshold
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._trained_at: Optional[datetime] = None
        self._feature_columns = self.FEATURE_COLUMNS

        # Try to load a pre-trained model from disk on startup
        self._load_model()

    # ─────────────────────────────────────────────
    # Training
    # ─────────────────────────────────────────────

    def train_baseline(self, dataframe: pd.DataFrame) -> Dict[str, Any]:
        """
        Trains the Isolation Forest on historical log data.

        The model learns the 'normal' multi-dimensional feature space of the
        application. Anomalies are observations that require fewer random
        partitions to isolate — they sit in sparse regions of feature space.

        Args:
            dataframe: DataFrame with at least the columns in FEATURE_COLUMNS.
                       Should represent at least 2 weeks of normal traffic.

        Returns:
            Training summary including sample count and feature statistics.
        """
        df = self._prepare_features(dataframe)
        if df.empty:
            raise ValueError("DataFrame is empty or missing required feature columns.")

        if len(df) < 50:
            logger.warning(
                f"Training on only {len(df)} samples — baseline may be unreliable. "
                "Recommend collecting at least 1000 samples for production."
            )

        # Scale features — IsolationForest is not scale-invariant in practice
        # because unscaled high-magnitude features dominate partitioning
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(df[self._feature_columns])

        self._model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=42,
            n_jobs=-1,  # Use all CPU cores for training
        )
        self._model.fit(X_scaled)
        self._trained_at = datetime.utcnow()

        # Persist model so it survives service restarts
        self._save_model()

        feature_stats = df[self._feature_columns].describe().to_dict()
        logger.info(
            f"Anomaly baseline trained on {len(df)} samples at {self._trained_at}."
        )

        return {
            "status": "trained",
            "sample_count": len(df),
            "trained_at": self._trained_at.isoformat(),
            "feature_stats": feature_stats,
            "contamination": self._contamination,
        }

    # ─────────────────────────────────────────────
    # Inference
    # ─────────────────────────────────────────────

    def predict_anomaly(
        self, current_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Scores a single observation against the trained baseline.

        Anomaly score semantics (IsolationForest convention):
        - Score near  0.0 → normal (hard to isolate)
        - Score near -1.0 → extreme anomaly (isolated quickly)
        - Our threshold (default -0.1) triggers an alert

        The method also identifies WHICH features deviated most, which is
        critical for SOC analysts who need to understand WHY an alert fired,
        not just that it did.

        Args:
            current_data: Dict with the same feature keys as FEATURE_COLUMNS.
                          Typically aggregated from the last 5-minute window.

        Returns:
            Dict with is_anomaly, anomaly_score, confidence, and deviation details.
        """
        if self._model is None or self._scaler is None:
            logger.warning("No trained model available. Returning neutral score.")
            return self._neutral_result(current_data, reason="Model not trained.")

        try:
            df = pd.DataFrame([current_data])
            df = self._prepare_features(df)

            if df.empty:
                return self._neutral_result(current_data, reason="Feature extraction failed.")

            X_scaled = self._scaler.transform(df[self._feature_columns])
            raw_score = float(self._model.score_samples(X_scaled)[0])
            is_anomaly = raw_score < self._score_threshold

            deviation_features = {}
            if is_anomaly:
                deviation_features = self._identify_deviating_features(
                    df[self._feature_columns].iloc[0]
                )

            # Convert score to 0-1 confidence (closer to -1 = higher confidence)
            confidence = min(1.0, max(0.0, abs(raw_score) * 2))

            result = {
                "is_anomaly": is_anomaly,
                "anomaly_score": round(raw_score, 4),
                "confidence": round(confidence, 4),
                "deviation_features": deviation_features,
                "detected_at": datetime.utcnow().isoformat(),
                "threshold_used": self._score_threshold,
            }

            if is_anomaly:
                logger.warning(
                    f"Anomaly detected! Score: {raw_score:.4f} | "
                    f"Deviating features: {list(deviation_features.keys())}"
                )

            return result

        except Exception as e:
            logger.error(f"Anomaly prediction failed: {e}")
            return self._neutral_result(current_data, reason=str(e))

    def _identify_deviating_features(
        self, observation: pd.Series
    ) -> Dict[str, float]:
        """
        Computes per-feature deviation from the scaler's learned mean.
        Returns only features that deviate by more than 2 standard deviations
        (keeping alert context focused — SOC analysts don't need a list of 
        features that are all within normal range).
        """
        mean = self._scaler.mean_
        std = np.sqrt(self._scaler.var_)
        deviations = {}

        for i, feature in enumerate(self._feature_columns):
            if std[i] == 0:
                continue
            z_score = (observation.iloc[i] - mean[i]) / std[i]
            if abs(z_score) > 2.0:
                deviations[feature] = round(float(z_score), 2)

        return deviations

    # ─────────────────────────────────────────────
    # Feature Engineering
    # ─────────────────────────────────────────────

    def _prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalizes and fills feature columns.
        Handles missing features gracefully — not all log sources provide
        all features (e.g., network logs don't have 'endpoint' data).
        """
        for col in self._feature_columns:
            if col not in df.columns:
                df[col] = 0.0

        df = df[self._feature_columns].fillna(0.0).astype(float)
        return df

    def aggregate_logs_to_features(
        self, logs: List[Dict[str, Any]], window_minutes: int = 5
    ) -> Dict[str, float]:
        """
        Converts raw log events into the feature vector expected by the model.
        This is the bridge between Elasticsearch log retrieval and ML inference —
        the same aggregation logic must be used during both training and inference
        to prevent training-serving skew.
        """
        if not logs:
            return {col: 0.0 for col in self._feature_columns}

        df = pd.DataFrame(logs)
        total = len(df)
        errors = df[df["status_code"].between(400, 599)].shape[0] if "status_code" in df else 0
        latencies = df["latency_ms"].dropna() if "latency_ms" in df else pd.Series([0.0])
        bytes_col = df["bytes_sent"].dropna() if "bytes_sent" in df else pd.Series([0.0])
        endpoints = df["endpoint"].nunique() if "endpoint" in df else 0

        return {
            "request_count": float(total),
            "error_rate": round(errors / max(total, 1), 4),
            "avg_latency_ms": round(latencies.mean() if len(latencies) else 0.0, 2),
            "bytes_per_request": round(bytes_col.mean() if len(bytes_col) else 0.0, 2),
            "unique_endpoints": float(endpoints),
            "p99_latency_ms": round(latencies.quantile(0.99) if len(latencies) else 0.0, 2),
        }

    # ─────────────────────────────────────────────
    # Model Persistence
    # ─────────────────────────────────────────────

    def _save_model(self) -> None:
        """Persist model and scaler to disk for warm restarts."""
        try:
            with open(MODEL_DIR / "isolation_forest.pkl", "wb") as f:
                pickle.dump({"model": self._model, "scaler": self._scaler, "trained_at": self._trained_at}, f)
            logger.info("Anomaly model saved to disk.")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def _load_model(self) -> None:
        """Attempt to restore a previously trained model from disk."""
        model_path = MODEL_DIR / "isolation_forest.pkl"
        if not model_path.exists():
            logger.info("No pre-trained anomaly model found. Train via /api/v1/ml/train.")
            return
        try:
            with open(model_path, "rb") as f:
                data = pickle.load(f)
            self._model = data["model"]
            self._scaler = data["scaler"]
            self._trained_at = data.get("trained_at")
            logger.info(f"Loaded anomaly model trained at {self._trained_at}.")
        except Exception as e:
            logger.error(f"Failed to load saved model: {e}")

    @property
    def is_trained(self) -> bool:
        return self._model is not None and self._scaler is not None

    @property
    def model_info(self) -> Dict[str, Any]:
        return {
            "is_trained": self.is_trained,
            "trained_at": self._trained_at.isoformat() if self._trained_at else None,
            "n_estimators": self._n_estimators,
            "contamination": self._contamination,
            "score_threshold": self._score_threshold,
            "features": self._feature_columns,
        }

    def _neutral_result(
        self, current_data: Dict[str, Any], reason: str = ""
    ) -> Dict[str, Any]:
        return {
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "confidence": 0.0,
            "deviation_features": {},
            "detected_at": datetime.utcnow().isoformat(),
            "threshold_used": self._score_threshold,
            "warning": reason,
        }
