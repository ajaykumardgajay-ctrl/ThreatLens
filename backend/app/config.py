"""Central configuration and default thresholds for TRACEPOINT."""

from pathlib import Path
from typing import Dict, List
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or defaults."""

    model_config = SettingsConfigDict(
        env_prefix="TRACEPOINT_",
        env_file=str(BACKEND_DIR / ".env"),
        extra="ignore",
    )

    db_path: str = str(DATA_DIR / "tracepoint.db")
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Rule-based detection settings
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 120
    impossible_travel_speed_kmh: float = 800.0
    unusual_login_start_hour: int = 7
    unusual_login_end_hour: int = 20
    outbound_spike_multiplier: float = 10.0
    outbound_min_bytes: int = 50 * 1024 * 1024  # 50 MB minimum floor

    # Correlation & graph settings
    correlation_window_minutes: int = 45
    ml_anomaly_threshold: float = 60.0

    # Risk scoring weights (configurable)
    score_weights: Dict[str, int] = {
        "brute_force": 25,
        "impossible_travel": 20,
        "privilege_escalation": 25,
        "sensitive_resource_access": 15,
        "data_exfiltration": 11,
        "unusual_login_time": 10,
        "ml_anomaly": 12,
    }

    # Optional LLM integration
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_base_url: str = "https://api.openai.com/v1"

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
