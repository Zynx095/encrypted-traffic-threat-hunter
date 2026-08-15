"""
Abstract base class for dataset adapters.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from pathlib import Path

class DatasetAdapter(ABC):
    dataset_id: str
    dataset_name: str
    research_role: str

    @abstractmethod
    def discover(self) -> List[Path]:
        pass

    @abstractmethod
    def extract_metadata(self, filepath: Path) -> Dict[str, Any]:
        pass

    @abstractmethod
    def normalize_metadata(self, raw_metadata: Dict[str, Any]) -> Dict[str, Any]:
        pass
