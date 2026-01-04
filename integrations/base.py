from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class Integration(ABC):
    name: str

    @abstractmethod
    async def analyze(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        pass

    def format_result(self, data: Dict[str, Any]) -> str:
        return f"🔍 *{self.name}*:\n{self._format(data)}"

    @abstractmethod
    def _format(self, data: Dict[str, Any]) -> str:
        pass
