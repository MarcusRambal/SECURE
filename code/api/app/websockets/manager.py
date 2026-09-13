import asyncio
from collections import defaultdict
from typing import DefaultDict, Set

from fastapi import WebSocket


class WebSocketManager:
	def __init__(self) -> None:
		self.connections: DefaultDict[str, Set[WebSocket]] = defaultdict(set)
		self._lock = asyncio.Lock()

	async def connect(self, task_id: str, websocket: WebSocket) -> None:
		await websocket.accept()
		async with self._lock:
			self.connections[task_id].add(websocket)

	async def disconnect(self, task_id: str, websocket: WebSocket) -> None:
		async with self._lock:
			task_connections = self.connections.get(task_id)
			if not task_connections:
				return
			task_connections.discard(websocket)
			if not task_connections:
				self.connections.pop(task_id, None)

	async def broadcast(self, task_id: str, event: dict) -> None:
		async with self._lock:
			recipients = tuple(self.connections.get(task_id, ()))

		is_terminal = event.get("eventType") in {"SCAN_COMPLETE", "SCAN_ERROR"}
		disconnected = []
		for websocket in recipients:
			try:
				await websocket.send_json(event)
				if is_terminal:
					await websocket.close(code=1000, reason="Tarea finalizada")
					disconnected.append(websocket)
			except Exception:
				disconnected.append(websocket)

		for websocket in disconnected:
			await self.disconnect(task_id, websocket)


websocket_manager = WebSocketManager()
