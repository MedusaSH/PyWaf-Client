from pydantic import BaseModel
from typing import Dict, Any, Optional


class TrendData(BaseModel):
    value: float
    is_positive: bool


class MetricsResponse(BaseModel):
    requests_blocked: int
    false_positives: int
    response_time_avg_ms: float
    top_attacking_ips: list[dict[str, Any]]
    most_targeted_endpoints: list[dict[str, Any]]
    threat_categories: dict[str, int]
    trends: Optional[dict[str, TrendData]] = None

