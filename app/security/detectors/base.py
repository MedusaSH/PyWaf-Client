from abc import ABC, abstractmethod
from typing import Optional


class BaseDetector(ABC):
    @abstractmethod
    def detect(self, payload: str) -> tuple[bool, Optional[str]]:
        pass

    def normalize_payload(self, payload: str) -> str:
        return payload.lower().strip()

