export interface ScanConfigPayload {
  targetUrl: string;
  category: string;
  attackType: string;
}

export interface ScrapingEndpoint {
  method: string;
  path: string;
  query_parameters: string[];
  [key: string]: unknown;
}

export interface ScrapingRequest {
  id: string;
  method: string;
  url: string;
  path: string;
  request_line: string;
  query_parameters: string[];
  query_values: Record<string, unknown>;
  resource_type: string;
  request_headers: Record<string, unknown>;
  request_body: Record<string, unknown> | null;
  response: {
    status: number | null;
    status_text: string;
    headers: Record<string, unknown>;
    body: {
      captured: boolean;
      content_type: string;
      data: unknown;
    };
  };
  observed_on: string[];
  [key: string]: unknown;
}

export interface ScrapingReport {
  target: string;
  observed_endpoints: ScrapingEndpoint[];
  requests: ScrapingRequest[];
  [key: string]: unknown;
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

export interface ScanEndpoint {
    endpoint: string;
    method: string;
    targetId?: string;
    requestId?: string;
    reason?: string;
    recommendedTool?: string;
}

export interface AgentWebSocketEvent {
    taskId: string;
    timestamp: string;
    eventType: EventType;
    agentName: 'orquestador' | 'scanner' | 'attacker' | 'reporter' | 'recon' | 'validate';
    payload: {
        message: string;
        details?: Record<string, unknown> & {
            endpoints?: ScanEndpoint[];
        };
        timings?: PipelineTimings;
      finalReport?: string;
      error?: string;
        endpoints?: ScanEndpoint[];
        vulnerability?: {
            title: string;
            severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO';
            endpoint?: string;
            parameter?: string;
            method?: string;
            evidence?: string;
            confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
            toolsUsed?: string[];
            verificationSteps?: string;
            pocScript?: string;
        }
    }
    durationMs?: number;
}