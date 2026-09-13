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


export interface AgentWebSocketEvent {
    taskId: string;
    timestamp: string;
    eventType: EventType;
    agentName: 'orquestador' | 'scanner' | 'attacker' | 'reporter';
    payload: {
        message: string;
        details?: Record<string, unknown>;
      finalReport?: string;
      error?: string;
        vulnerability?: {
            title:string;
            cvssScore:number;
            severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
            pocScript?: string;
        }
    }
}