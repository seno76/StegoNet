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


def _payload_entropy(data: bytes) -> float:
    """Compute Shannon entropy of payload bytes (bits per byte)."""
    if not data:
        return 0.0
    counts = np.zeros(256)
    for b in data:
        counts[b] += 1
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def extract_features(
    field_values: list[int],
    timestamps: list[float],
    packet_sizes: list[int] | None = None,
    payloads: list[bytes] | None = None,
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
        - Payload entropy (bits/byte)
        - Payload length

    Args:
        field_values: List of field values (e.g., IP IDs).
        timestamps: List of packet timestamps.
        packet_sizes: Optional list of packet sizes.
        payloads: Optional list of raw payload bytes.

    Returns:
        2D numpy array of shape (n_samples, n_features).
    """
    n = len(field_values)
    if n < 2:
        return np.empty((0, 9))

    values = np.array(field_values, dtype=float)
    times = np.array(timestamps, dtype=float)
    sizes = np.array(packet_sizes, dtype=float) if packet_sizes else np.zeros(n)
    pays = payloads if payloads else [b""] * n

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
            _payload_entropy(pays[i]),
            float(len(pays[i])),
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


@dataclass
class RFResult:
    """Result of RandomForest classification."""

    accuracy: float
    predictions: list[int]
    feature_importances: list[float]


def detect_random_forest(
    train_X: np.ndarray,
    train_y: np.ndarray,
    test_X: np.ndarray,
    test_y: np.ndarray,
) -> RFResult:
    """Train RandomForest on labeled data and predict on test set.

    Args:
        train_X: Training feature matrix.
        train_y: Training labels (0=normal, 1=stego).
        test_X: Test feature matrix.
        test_y: Test labels.

    Returns:
        RFResult with predictions and accuracy.
    """
    scaler = StandardScaler()
    scaled_train = scaler.fit_transform(train_X)
    scaled_test = scaler.transform(test_X)

    clf = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        max_depth=10,
    )
    clf.fit(scaled_train, train_y)

    predictions = clf.predict(scaled_test).tolist()
    accuracy = sum(1 for p, t in zip(predictions, test_y) if p == t) / len(test_y)

    return RFResult(
        accuracy=accuracy,
        predictions=predictions,
        feature_importances=clf.feature_importances_.tolist(),
    )
