"""Machine learning based covert channel detection.

Uses IsolationForest for anomaly detection on packet features.
Can optionally train a RandomForest classifier if labeled data is available.
"""

from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler


@dataclass
class MLResult:
    """Result of ML-based detection."""

    method: str
    anomaly_ratio: float
    predictions: list[int]  # -1 for anomaly, 1 for normal (IsolationForest)
    confidence: float
    is_anomaly: bool
    details: str = ""


def extract_features(
    field_values: list[int],
    timestamps: list[float],
    packet_sizes: list[int] | None = None,
) -> np.ndarray:
    """Extract feature vectors from packet data.

    Features per packet (sliding window of 5):
        - Field value
        - Delta from previous value
        - Inter-packet delay
        - Packet size (if available)
        - Rolling mean of field values
        - Rolling std of field values
        - Rolling mean of IPD

    Args:
        field_values: List of field values (e.g., IP IDs).
        timestamps: List of packet timestamps.
        packet_sizes: Optional list of packet sizes.

    Returns:
        2D numpy array of shape (n_samples, n_features).
    """
    n = len(field_values)
    if n < 2:
        return np.empty((0, 7))

    values = np.array(field_values, dtype=float)
    times = np.array(timestamps, dtype=float)
    sizes = np.array(packet_sizes, dtype=float) if packet_sizes else np.zeros(n)

    # Compute deltas
    value_deltas = np.diff(values, prepend=values[0])
    ipd = np.diff(times, prepend=times[0])

    # Rolling stats with window=5
    window = min(5, n)
    features = []
    for i in range(n):
        start = max(0, i - window + 1)
        win_vals = values[start : i + 1]
        win_ipd = ipd[start : i + 1]
        features.append([
            values[i],
            value_deltas[i],
            ipd[i],
            sizes[i],
            float(np.mean(win_vals)),
            float(np.std(win_vals)),
            float(np.mean(win_ipd)),
        ])

    return np.array(features)


def detect_isolation_forest(
    features: np.ndarray,
    contamination: float = 0.05,
) -> MLResult:
    """Run IsolationForest anomaly detection.

    Args:
        features: Feature matrix from extract_features().
        contamination: Expected fraction of anomalies.

    Returns:
        MLResult with predictions and anomaly ratio.
    """
    if len(features) < 10:
        return MLResult(
            method="isolation_forest",
            anomaly_ratio=0.0,
            predictions=[],
            confidence=0.0,
            is_anomaly=False,
            details="Insufficient data (< 10 samples)",
        )

    scaler = StandardScaler()
    scaled = scaler.fit_transform(features)

    clf = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
    )
    predictions = clf.fit_predict(scaled)
    scores = clf.decision_function(scaled)

    anomaly_count = int(np.sum(predictions == -1))
    anomaly_ratio = anomaly_count / len(predictions)
    mean_score = float(np.mean(scores))

    return MLResult(
        method="isolation_forest",
        anomaly_ratio=anomaly_ratio,
        predictions=predictions.tolist(),
        confidence=abs(mean_score),
        is_anomaly=anomaly_ratio > contamination * 2,
        details=(
            f"anomalies={anomaly_count}/{len(predictions)}, "
            f"ratio={anomaly_ratio:.4f}, mean_score={mean_score:.4f}"
        ),
    )


def train_classifier(
    features: np.ndarray,
    labels: np.ndarray,
) -> RandomForestClassifier:
    """Train a RandomForest classifier on labeled data.

    Args:
        features: Feature matrix.
        labels: Binary labels (0=normal, 1=stego).

    Returns:
        Trained RandomForestClassifier.
    """
    scaler = StandardScaler()
    scaled = scaler.fit_transform(features)

    clf = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        max_depth=10,
    )
    clf.fit(scaled, labels)
    return clf
