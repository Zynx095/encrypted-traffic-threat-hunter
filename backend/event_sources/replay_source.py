import logging
import time
import pandas as pd
from pathlib import Path
from typing import Dict, Any, Optional
from backend.event_sources.base import EventSource

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class ReplayEventSource(EventSource):
    """
    PCAP / Parquet Dataset Replay Event Source.
    Yields deterministic, normalized flow records from research datasets.
    """
    def __init__(self):
        super().__init__(mode="REPLAY")
        self.state: str = "IDLE"
        self.source_id: str = "DS-008"
        self.df: Optional[pd.DataFrame] = None
        self.current_index: int = 0
        self.start_time: Optional[float] = None
        self._load_dataset()

    def _load_dataset(self):
        try:
            parquet_path = BASE_DIR / "data" / "processed" / "features" / "flows_behavioral_features.parquet"
            if not parquet_path.exists():
                parquet_path = BASE_DIR / "data" / "processed" / "v2" / "model_safe" / "model_safe_dataset.parquet"
                
            if parquet_path.exists():
                self.df = pd.read_parquet(parquet_path)
                logger.info(f"ReplayEventSource loaded {len(self.df)} flow records from {parquet_path.name}")
                if "dataset_id" in self.df.columns and not self.df.empty:
                    first_ds = str(self.df.iloc[0]["dataset_id"])
                    if first_ds and first_ds.lower() != "nan":
                        self.source_id = first_ds
            else:
                logger.warning(f"ReplayEventSource: Parquet dataset file not found at {parquet_path}")
        except Exception as e:
            logger.error(f"Failed to load dataset for ReplayEventSource: {e}")

    async def start(self, **kwargs) -> None:
        self.state = "PLAYING"
        self.current_index = 0
        self.start_time = time.time()

    async def stop(self) -> None:
        self.state = "STOPPED"

    def get_next_flow(self) -> Optional[Dict[str, Any]]:
        """
        Returns the next normalized flow record from the dataset, or None if end reached.
        """
        if self.df is None or len(self.df) == 0:
            return None
        if self.current_index >= len(self.df):
            return None
        
        row = self.df.iloc[self.current_index].to_dict()
        self.current_index += 1
        return row

    def get_status(self) -> Dict[str, Any]:
        total = len(self.df) if self.df is not None else 0
        elapsed = round(time.time() - self.start_time, 2) if (self.start_time and self.state == "PLAYING") else 0.0
        return {
            "status": self.state,
            "mode": "REPLAY",
            "source_id": self.source_id,
            "total_rows": total,
            "current_index": self.current_index,
            "elapsed_seconds": elapsed
        }
