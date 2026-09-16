"use client";

import { useEffect, useState } from "react";
import { AgentWebSocketEvent } from "@/types/scan";

export const useAgentSocket = (taskId: string | null) => {
  const [eventState, setEventState] = useState<{
    taskId: string | null;
    events: AgentWebSocketEvent[];
  }>({ taskId: null, events: [] });
  const [connectedTaskId, setConnectedTaskId] = useState<string | null>(null);

  useEffect(() => {
    if (!taskId) return;

    const wsBaseUrl = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";
    const wsUrl = `${wsBaseUrl.replace(/\/$/, "")}/ws/scans/${taskId}`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      console.log(`[WS Connected] Escuchando tarea: ${taskId}`);
      setConnectedTaskId(taskId);
    };

    socket.onmessage = (event) => {
      try {
        const data: AgentWebSocketEvent = JSON.parse(event.data);
        setEventState((previous) => ({
          taskId,
          events: previous.taskId === taskId
            ? [...previous.events, data]
            : [data],
        }));

        if (data.eventType === "SCAN_COMPLETE" || data.eventType === "SCAN_ERROR") {
          socket.close(1000, "Tarea finalizada");
        }
      } catch (err) {
        console.error("Error al parsear el evento del socket:", err);
      }
    };

    socket.onerror = (error) => {
      console.error("[WS Error]", error);
    };

    socket.onclose = () => {
      console.log(`[WS Closed] Tarea: ${taskId}`);
      setConnectedTaskId((currentTaskId) => currentTaskId === taskId ? null : currentTaskId);
    };

    return () => {
      socket.close();
    };
  }, [taskId]);

  const events = eventState.taskId === taskId ? eventState.events : [];
  const isFinished = events.some((event) =>
    event.eventType === "SCAN_COMPLETE" || event.eventType === "SCAN_ERROR"
  );
  const isFailed = events.some((event) => event.eventType === "SCAN_ERROR");
  const finalEvent = events.find((event) => event.eventType === "SCAN_COMPLETE");

  return {
    events,
    isConnected: connectedTaskId === taskId,
    isFinished,
    isFailed,
    finalReport: finalEvent?.payload.finalReport,
  };
};