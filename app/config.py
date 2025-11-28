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
    
    max_latency_ms: int = 50
    max_memory_mb: int = 512
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


settings = Settings()

