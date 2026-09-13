// Define el contrato de datos del payload
export interface CreateTaskPayload {
  targetUrl: string;
  category: string;
  attackType: string;
  agentModels: {
    scanner: string;
    attacker: string;
    reporter: string;
  };
}

export interface TaskResponse {
  taskId: string;
  status: string;
  message?: string;
}

const isServer = typeof window === 'undefined';

const API_BASE_URL = isServer
  ? (process.env.INTERNAL_API_URL || 'http://api:8000')
  : (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000');

export const scanService = {
  async createScanTask(payload: CreateTaskPayload): Promise<TaskResponse> {
    const response = await fetch(`${API_BASE_URL}/api/task`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        target_url: payload.targetUrl,
        category: payload.category,
        attack_type: payload.attackType,
        agent_models: payload.agentModels,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `Error del servidor (${response.status})`);
    }

    const data = await response.json();

    return {
      taskId: data.task_id ?? data.taskId,
      status: data.status,
      message: data.message,
    };
  },
};