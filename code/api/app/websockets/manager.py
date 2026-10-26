import asyncio
from collections import defaultdict
from typing import DefaultDict, Set

from fastapi import WebSocket


class WebSocketManager:
	def __init__(self) -> None:
		self.connections: DefaultDict[str, Set[WebSocket]] = defaultdict(set)
		self.event_history: DefaultDict[str, list[dict]] = defaultdict(list)
		self._lock = asyncio.Lock()

	async def connect(self, task_id: str, websocket: WebSocket) -> None:
		await websocket.accept()
		disconnected = False
		try:
			async with self._lock:
				self.connections[task_id].add(websocket)
				history = self.event_history.pop(task_id, [])
				for event in history:
					await websocket.send_json(event)
					if event.get("eventType") in {"SCAN_COMPLETE", "SCAN_ERROR"}:
						await websocket.close(code=1000, reason="Tarea finalizada")
						disconnected = True
						break
		except Exception:
			await self.disconnect(task_id, websocket)
			raise
		if disconnected:
			await self.disconnect(task_id, websocket)

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
			if not recipients:
				self.event_history[task_id].append(event)
				if len(self.event_history[task_id]) > 250:
					self.event_history[task_id].pop(0)
				while len(self.event_history) > 100:
					self.event_history.pop(next(iter(self.event_history)))
				return

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
