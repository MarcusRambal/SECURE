// Define el contrato de datos del payload
export interface CreateTaskPayload {
  targetUrl: string;
  category: string;
  attackType: string;
  sessionToken?: string;
  // JWT de sesión, solo presente en ataques que lo requieren (jwt).
  token?: string;
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
    // El token solo se envía si está presente (no contaminar el payload de ataques sin auth).
    const body: Record<string, unknown> = {
      target_url: payload.targetUrl,
      category: payload.category,
      attack_type: payload.attackType,
    };
    const token =
      payload.token?.trim() ||
      (payload.attackType === 'jwt' || payload.attackType === 'crypto_inspector'
        ? payload.sessionToken?.trim()
        : undefined);
    if (token) {
      body.token = token;
    }
    if (payload.attackType !== 'jwt' && payload.sessionToken?.trim()) {
      body.session_token = payload.sessionToken.trim();
    }

    const response = await fetch(`${API_BASE_URL}/api/task`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
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