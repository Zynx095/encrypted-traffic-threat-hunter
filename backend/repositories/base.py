from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BaseRepository(ABC):
    """
    Abstract Repository Interface for ETTH Persistence Layer.
    Isolates business logic from underlying storage (In-memory, JSON, SQLite, PostgreSQL).
    """
    @abstractmethod
    def all(self) -> List[Any]:
        pass

    @abstractmethod
    def get(self, entity_id: str) -> Optional[Any]:
        pass

    @abstractmethod
    def create(self, data: Dict[str, Any]) -> Any:
        pass

    @abstractmethod
    def update(self, entity_id: str, data: Dict[str, Any]) -> Optional[Any]:
        pass

    @abstractmethod
    def delete(self, entity_id: str) -> bool:
        pass
