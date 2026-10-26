export interface ScanConfigPayload {
  targetUrl: string;
  category: string;
  attackType: string;
  agentModels: {
    scanner: string;
    attacker: string;
    reporter: string;
  };
}

export interface ScanInitResponse {
    taskId: string;
  status: string;
  message?: string;
}

export type EventType = 'AGENT_THOUGHT' | 'TOOL_EXECUTION' | 'VULN_DETECTED'
| 'SCAN_COMPLETE'
| 'SCAN_ERROR';

export interface ToolTiming {
    tool: string;
    publishMs?: number;
    queueWaitMs?: number | null;
    processingMs?: number;
    roundTripMs?: number;
    status?: string;
}

export interface PipelineStageTiming {
    durationMs?: number;
    publishMs?: number;
    queueWaitMs?: number | null;
    processingMs?: number;
    roundTripMs?: number;
    status?: string;
    tools?: ToolTiming[];
}

export interface PipelineTimings {
    queueWaitMs?: number;
    totalMs?: number;
    stages?: Record<string, PipelineStageTiming>;
}

export interface AgentWebSocketEvent {
    taskId: string;
    timestamp: string;
    eventType: EventType;
    agentName: 'orquestador' | 'scanner' | 'attacker' | 'reporter' | 'recon' | 'validate';
    payload: {
        message: string;
        details?: Record<string, unknown>;
        timings?: PipelineTimings;
      finalReport?: string;
      error?: string;
        vulnerability?: {
            title: string;
            severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO';
            endpoint?: string;
            evidence?: string;
            confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
            toolsUsed?: string[];
            pocScript?: string;
        }
    }
    durationMs?: number;
}