from abc import ABC, abstractmethod
from typing import Dict, Any

class EventSource(ABC):
    """
    Abstract Event Source Interface for ETTH Flow Acquisition.
    Decouples source flow acquisition from detection pipeline, model internals, and presentation layers.
    """
    def __init__(self, mode: str = "REPLAY"):
        self.mode: str = mode

    @abstractmethod
    async def start(self, **kwargs) -> None:
        """Starts flow acquisition."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stops flow acquisition cleanly."""
        pass

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Returns operational acquisition status and diagnostic telemetry."""
        pass
