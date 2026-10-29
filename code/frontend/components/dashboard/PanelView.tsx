"use client";

import { Accordion, type AccordionItem } from "./Accordion";
import type { AgentWebSocketEvent } from "@/types/scan";
import styles from "./PanelView.module.css";

interface PanelViewProps {
  taskId: string | null;
  events: AgentWebSocketEvent[];
  vulnerabilities: NonNullable<AgentWebSocketEvent["payload"]["vulnerability"]>[];
  finalReport?: string;
  isConnected: boolean;
  isFinished: boolean;
  isFailed: boolean;
}

const formatDuration = (durationMs: number) =>
  `${new Intl.NumberFormat("es-CO", { maximumFractionDigits: 2 }).format(durationMs / 1000)} s`;

export const PanelView = ({
  taskId,
  events,
  vulnerabilities,
  finalReport,
  isConnected,
  isFinished,
  isFailed,
}: PanelViewProps) => {
  const status = !taskId
    ? { label: "Sin escaneo", className: styles.statusIdle }
    : isFailed
      ? { label: "Error", className: styles.statusError }
      : isFinished
        ? { label: "Completado", className: styles.statusComplete }
        : { label: isConnected ? "Conectado" : "Esperando agentes", className: styles.statusPending };

  const endpointItems: AccordionItem[] = events.map((event, index) => ({
    id: `${event.timestamp}-${index}`,
    header: event.payload.message,
    content: (
      <>
        <span><strong>Agente:</strong> {event.agentName}</span>
        {event.durationMs !== undefined && <span>Duración: {formatDuration(event.durationMs)}</span>}
        {event.payload.details && <pre>{JSON.stringify(event.payload.details, null, 2)}</pre>}
      </>
    ),
  }));

  const vulnerabilityItems: AccordionItem[] = vulnerabilities.map((vulnerability, index) => ({
    id: `${vulnerability.title}-${index}`,
    header: vulnerability.endpoint ?? vulnerability.title,
    content: (
      <>
        <span><strong>Ataque:</strong> {vulnerability.title}</span>
        <span><strong>Severidad:</strong> {vulnerability.severity}</span>
        {vulnerability.confidence && <span><strong>Confianza:</strong> {vulnerability.confidence}</span>}
        {vulnerability.evidence && <span><strong>Evidencia:</strong> {vulnerability.evidence}</span>}
        {vulnerability.toolsUsed && vulnerability.toolsUsed.length > 0 && (
          <span><strong>Herramientas:</strong> {vulnerability.toolsUsed.join(", ")}</span>
        )}
        {vulnerability.pocScript && <pre>{vulnerability.pocScript}</pre>}
      </>
    ),
  }));

  return (
    <div className={styles.panelContainer}>
      <header className={styles.taskInfo}>
        <code className={styles.taskId}>
          {taskId ?? "Configura y lanza un escaneo para ver los resultados."}
        </code>
        <span className={`${styles.status} ${status.className}`}>{status.label}</span>
      </header>

      <div className={styles.panelLayout}>
        <div className={styles.leftColumn}>
          <section className={styles.block}>
            <h2 className={styles.blockTitle}>Endpoints</h2>
            <Accordion items={endpointItems} emptyMessage="Aguardando eventos del orquestador..." />
          </section>

          <section className={styles.block}>
            <h2 className={styles.blockTitle}>Vulnerabilidades</h2>
            <Accordion items={vulnerabilityItems} emptyMessage="Aún no se han reportado vulnerabilidades." />
          </section>
        </div>

        <section className={`${styles.block} ${styles.reportBlock}`}>
          <h2 className={styles.blockTitle}>Reporte</h2>
          {finalReport ? (
            <p className={styles.reportText}>{finalReport}</p>
          ) : (
            <p className={styles.emptyMessage}>El informe final aparecerá aquí al completar el escaneo.</p>
          )}
        </section>
      </div>
    </div>
  );
};
