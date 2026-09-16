'use server';

import { scanService, CreateTaskPayload } from '../services/scanService';

export async function submitScanConfigAction(payload: CreateTaskPayload) {
  try {
    // 1. Aquí puedes agregar validaciones adicionales con Zod si lo requieres
    if (!payload.targetUrl) {
      return { success: false, error: 'La URL de destino es obligatoria.' };
    }

    // 2. Delegar la ejecución al servicio
    const result = await scanService.createScanTask(payload);

    return { success: true, data: result };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Error al procesar el escaneo';
    return { success: false, error: message };
  }
}