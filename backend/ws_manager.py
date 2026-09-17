import logging
from typing import List, Dict, Any, Union
from fastapi import WebSocket
from pydantic import ValidationError
from backend.schemas import ETTHStreamEvent

logger = logging.getLogger(__name__)

class ConnectionManager:
    """
    Manages WebSocket connections and broadcasts validated ETTH stream events.
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total active connections: {len(self.active_connections)}")

    def get_client_count(self) -> int:
        return len(self.active_connections)


    async def send_event(self, event: Union[ETTHStreamEvent, Dict[str, Any]], websocket: WebSocket):
        """
        Sends a single validated event to a specific WebSocket client.
        """
        try:
            if isinstance(event, ETTHStreamEvent):
                payload = event.model_dump()
            else:
                validated = ETTHStreamEvent.model_validate(event)
                payload = validated.model_dump()
                
            await websocket.send_json(payload)
        except ValidationError as val_err:
            logger.error(f"Failed to validate event before sending: {val_err}")
        except Exception as e:
            logger.error(f"Error sending message to client: {e}")
            self.disconnect(websocket)

    async def broadcast(self, event: Union[ETTHStreamEvent, Dict[str, Any]]):
        """
        Validates and broadcasts an event to all connected clients.
        """
        if not self.active_connections:
            return

        try:
            if isinstance(event, ETTHStreamEvent):
                payload = event.model_dump()
            else:
                validated = ETTHStreamEvent.model_validate(event)
                payload = validated.model_dump()
        except ValidationError as val_err:
            logger.error(f"Validation error in broadcast payload. Dropping invalid event: {val_err}")
            return

        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except Exception as e:
                logger.warning(f"Error broadcasting to client, scheduling disconnect: {e}")
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()
