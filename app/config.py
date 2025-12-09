from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    database_url: str
    redis_url: str = "redis://localhost:6379/0"
    secret_key: str
    environment: str = "development"
    log_level: str = "INFO"
    
    sql_injection_enabled: bool = True
    sql_injection_sensitivity: str = "high"
    xss_protection_enabled: bool = True
    xss_modes: list[str] = ["reflected", "stored", "dom"]
    
    rate_limiting_enabled: bool = True
    rate_limit_requests_per_minute: int = 100
    rate_limit_burst: int = 50
    rate_limit_by_ip: bool = True
    
    ddos_protection_enabled: bool = True
    ddos_max_connections_per_ip: int = 50
    
    ip_reputation_enabled: bool = True
    behavioral_analysis_enabled: bool = True
    adaptive_rate_limiting_enabled: bool = True
    challenge_system_enabled: bool = True
    tls_fingerprinting_enabled: bool = True
    staged_ddos_mitigation_enabled: bool = True
    
    reputation_malicious_threshold: float = 70.0
    reputation_suspicious_threshold: float = 40.0
    
    pow_challenge_difficulty_min: int = 1
    pow_challenge_difficulty_max: int = 5
    challenge_bypass_threshold: int = 3
    
    headless_detection_enabled: bool = True
    headless_detection_confidence_threshold: float = 0.6
    
    javascript_tarpit_enabled: bool = True
    javascript_tarpit_complexity_min: int = 4
    javascript_tarpit_complexity_max: int = 7
    javascript_tarpit_min_solve_time_ms: float = 100.0
    javascript_tarpit_max_solve_time_ms: float = 30000.0
    
    encrypted_cookie_challenge_enabled: bool = True
    encrypted_cookie_ttl: int = 3600
    
    syn_cookie_enabled: bool = True
    syn_cookie_max_requests_per_ip: int = 10
    
    connection_state_protection_enabled: bool = True
    max_half_open_connections: int = 1000
    max_total_connections: int = 5000
    connection_threshold_warning: float = 0.7
    connection_threshold_critical: float = 0.9
    
    geo_filtering_enabled: bool = False
    geo_attack_threshold: int = 100
    geo_analysis_window_minutes: int = 5
    
    connection_metrics_enabled: bool = True
    connection_metrics_window_minutes: int = 5
    low_and_slow_threshold_bytes_per_sec: float = 10.0
    low_and_slow_min_duration_seconds: int = 60
    
    behavioral_malice_scoring_enabled: bool = True
    malice_score_error_rate_weight: float = 0.25
    malice_score_low_and_slow_weight: float = 0.20
    malice_score_regular_timing_weight: float = 0.20
    malice_score_reputation_weight: float = 0.20
    malice_score_tls_weight: float = 0.15
    malice_score_critical_threshold: float = 0.8
    malice_score_high_threshold: float = 0.6
    malice_score_medium_threshold: float = 0.4
    
    max_latency_ms: int = 50
    max_memory_mb: int = 512
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


settings = Settings()

