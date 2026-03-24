"""Configuration models using Pydantic."""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ChannelConfig(BaseModel):
    type: str = "ip-id"
    bits_per_packet: int = 16


class CryptoConfig(BaseModel):
    algorithm: str = "aes-256-gcm"
    kdf: str = "argon2id"
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536


class TimingConfig(BaseModel):
    rate_pps: int = 10
    jitter_factor: float = 0.1


class CoverTrafficConfig(BaseModel):
    generate_noise: bool = True
    noise_ratio: int = 3


class DetectionConfig(BaseModel):
    chi_squared_alpha: float = 0.05
    ipd_window: int = 100
    ml_contamination: float = 0.05


class StatsConfig(BaseModel):
    db_path: str = "~/.netstego/stats.db"
    realtime: bool = True
    flush_interval_sec: int = 5


class AppConfig(BaseModel):
    channel: ChannelConfig = Field(default_factory=ChannelConfig)
    crypto: CryptoConfig = Field(default_factory=CryptoConfig)
    timing: TimingConfig = Field(default_factory=TimingConfig)
    cover_traffic: CoverTrafficConfig = Field(default_factory=CoverTrafficConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    stats: StatsConfig = Field(default_factory=StatsConfig)


def load_config(path: Path | None = None) -> AppConfig:
    """Load configuration from YAML file or return defaults."""
    if path is None:
        path = Path(__file__).parent.parent / "configs" / "default.yaml"
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return AppConfig(**data)
    return AppConfig()
