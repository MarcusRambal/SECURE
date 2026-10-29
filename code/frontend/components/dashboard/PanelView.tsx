"use client";

import { Fragment } from "react";
import type { AgentWebSocketEvent, ScanEndpoint } from "@/types/scan";
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

const stages = [
  { id: "recon", label: "Reconocimiento", agent: "recon" },
  { id: "validate", label: "Validación", agent: "validate" },
  { id: "reporter", label: "Reporte final", agent: "reporter" },
] as const;

const formatDuration = (durationMs: number) =>
  `${new Intl.NumberFormat("es-CO", { maximumFractionDigits: 2 }).format(durationMs / 1000)} s`;

const renderInlineMarkdown = (text: string, keyPrefix: string) =>
  text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, index) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={`${keyPrefix}-${index}`}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return <code key={`${keyPrefix}-${index}`}>{part.slice(1, -1)}</code>;
    }
    return <Fragment key={`${keyPrefix}-${index}`}>{part}</Fragment>;
  });

type ReportBlock =
  | { type: "heading"; level: number; text: string }
  | { type: "paragraph"; text: string }
  | { type: "list"; ordered: boolean; items: string[] }
  | { type: "code"; text: string }
  | { type: "rule" };

const parseReport = (report: string): ReportBlock[] => {
  const blocks: ReportBlock[] = [];
  const lines = report.split(/\r?\n/);
  let codeLines: string[] | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.startsWith("```")) {
      if (codeLines === null) {
        codeLines = [];
      } else {
        blocks.push({ type: "code", text: codeLines.join("\n") });
        codeLines = null;
      }
      continue;
    }

    if (codeLines !== null) {
      codeLines.push(rawLine);
      continue;
    }
    if (!line) continue;

    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      blocks.push({
        type: "heading",
        level: heading[1].length,
        text: heading[2],
      });
      continue;
    }
    if (/^(---+|\*\*\*+)$/.test(line)) {
      blocks.push({ type: "rule" });
      continue;
    }

    const listItem = line.match(/^(?:[-*+]\s+|(\d+)[.)]\s+)(.+)$/);
    if (listItem) {
      const ordered = Boolean(listItem[1]);
      const previousBlock = blocks.at(-1);
      if (previousBlock?.type === "list" && previousBlock.ordered === ordered) {
        previousBlock.items.push(listItem[2]);
      } else {
        blocks.push({ type: "list", ordered, items: [listItem[2]] });
      }
      continue;
    }

    const previousBlock = blocks.at(-1);
    if (previousBlock?.type === "paragraph") {
      previousBlock.text += ` ${line}`;
    } else {
      blocks.push({ type: "paragraph", text: line });
    }
  }

  if (codeLines !== null) {
    blocks.push({ type: "code", text: codeLines.join("\n") });
  }
  return blocks;
};

const MarkdownReport = ({ report }: { report: string }) => (
  <div className={styles.reportContent}>
    {parseReport(report).map((block, index) => {
      if (block.type === "heading") {
        const Heading = `h${Math.min(block.level + 1, 4)}` as "h2" | "h3" | "h4";
        return (
          <Heading className={styles.reportHeading} key={`heading-${index}`}>
            {renderInlineMarkdown(block.text, `heading-${index}`)}
          </Heading>
        );
      }
      if (block.type === "paragraph") {
        return (
          <p key={`paragraph-${index}`}>
            {renderInlineMarkdown(block.text, `paragraph-${index}`)}
          </p>
        );
      }
      if (block.type === "list") {
        const List = block.ordered ? "ol" : "ul";
        return (
          <List className={styles.reportList} key={`list-${index}`}>
            {block.items.map((item, itemIndex) => (
              <li key={`list-${index}-${itemIndex}`}>
                {renderInlineMarkdown(item, `list-${index}-${itemIndex}`)}
              </li>
            ))}
          </List>
        );
      }
      if (block.type === "code") {
        return (
          <pre className={styles.reportCode} key={`code-${index}`}>
            <code>{block.text}</code>
          </pre>
        );
      }
      return <hr className={styles.reportRule} key={`rule-${index}`} />;
    })}
  </div>
);

const getEndpoints = (events: AgentWebSocketEvent[]): ScanEndpoint[] => {
  const reconEvents = [...events].reverse().filter(
    (event) => event.agentName === "recon",
  );
  for (const event of reconEvents) {
    const endpoints =
      event.payload.endpoints ?? event.payload.details?.endpoints;
    if (Array.isArray(endpoints) && endpoints.length > 0) {
      return endpoints;
    }
  }
  return [];
};

export const PanelView = ({
  taskId,
  events,
  vulnerabilities,
  finalReport,
  isConnected,
  isFinished,
  isFailed,
}: PanelViewProps) => {
  const lastStageEvent = [...events].reverse().find((event) =>
    stages.some((stage) => stage.agent === event.agentName),
  );
  const currentStageId = lastStageEvent?.agentName ?? "recon";
  const failedStage = [...events].reverse().find(
    (event) =>
      event.eventType === "TOOL_EXECUTION" &&
      event.payload.details?.status === "ERROR" &&
      stages.some((stage) => stage.agent === event.agentName),
  )?.agentName;

  const completedStages = new Set(
    events
      .filter(
        (event) =>
          event.eventType === "TOOL_EXECUTION" &&
          event.payload.details?.status !== "ERROR" &&
          stages.some((stage) => stage.agent === event.agentName),
      )
      .map((event) => event.agentName),
  );

  const currentStage = stages.find((stage) => stage.id === currentStageId);
  const statusLabel = !taskId
    ? "Sin escaneo"
    : isFailed
      ? "Escaneo con error"
      : isFinished
        ? "Escaneo completado"
        : isConnected
          ? "En proceso"
          : "Conectando";
  const endpoints = getEndpoints(events);
  const severityCounts = vulnerabilities.reduce<Record<string, number>>(
    (counts, vulnerability) => {
      counts[vulnerability.severity] = (counts[vulnerability.severity] ?? 0) + 1;
      return counts;
    },
    {},
  );

  return (
    <div className={styles.panelContainer}>
      <header className={styles.taskHeader}>
        <div>
          <p className={styles.eyebrow}>Seguimiento de auditoría</p>
          <h1 className={styles.pageTitle}>Trazabilidad del escaneo</h1>
          <code className={styles.taskId}>
            {taskId ?? "Configura y lanza un escaneo para comenzar."}
          </code>
        </div>
        <span
          className={`${styles.status} ${
            isFailed
              ? styles.statusError
              : isFinished
                ? styles.statusComplete
                : styles.statusPending
          }`}
        >
          <span className={styles.statusIndicator} />
          {statusLabel}
        </span>
      </header>

      <section className={styles.stageSection} aria-labelledby="stage-title">
        <div className={styles.sectionHeading}>
          <div>
            <p className={styles.eyebrow}>Pipeline</p>
            <h2 className={styles.sectionTitle} id="stage-title">
              Etapa actual
            </h2>
          </div>
          {currentStage && !isFinished && (
            <span className={styles.currentStageLabel}>{currentStage.label}</span>
          )}
        </div>
        <ol className={styles.stageList}>
          {stages.map((stage, index) => {
            const isStageComplete =
              completedStages.has(stage.agent) || (isFinished && !isFailed);
            const isStageFailed =
              isFailed && (failedStage ?? currentStageId) === stage.agent;
            const isStageCurrent =
              !isFinished && !isStageComplete && stage.id === currentStageId;
            const stageEvent = [...events]
              .reverse()
              .find((event) => event.agentName === stage.agent);
            const stateClass = isStageFailed
              ? styles.stageFailed
              : isStageComplete
                ? styles.stageComplete
                : isStageCurrent
                  ? styles.stageCurrent
                  : styles.stagePending;

            return (
              <li
                className={`${styles.stageCard} ${stateClass}`}
                key={stage.id}
                aria-current={isStageCurrent ? "step" : undefined}
              >
                <span className={styles.stageNumber}>
                  {isStageFailed ? "!" : isStageComplete ? "✓" : `0${index + 1}`}
                </span>
                <div className={styles.stageCopy}>
                  <span className={styles.stageName}>{stage.label}</span>
                  <span className={styles.stageMessage}>
                    {isStageFailed
                      ? "La etapa encontró un error."
                      : stageEvent?.payload.message ??
                        (isStageCurrent
                          ? "Preparando la tarea..."
                          : "Pendiente")}
                  </span>
                  {stageEvent?.durationMs !== undefined && (
                    <span className={styles.stageDuration}>
                      {formatDuration(stageEvent.durationMs)}
                    </span>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      </section>

      <div className={styles.resultsGrid}>
        <section className={`${styles.panelCard} ${styles.endpointsCard}`}>
          <div className={styles.sectionHeading}>
            <div>
              <p className={styles.eyebrow}>Reconocimiento</p>
              <h2 className={styles.sectionTitle}>Endpoints a probar</h2>
            </div>
            <span className={styles.countBadge}>{endpoints.length}</span>
          </div>

          {endpoints.length > 0 ? (
            <ol className={styles.endpointList}>
              {endpoints.map((endpoint, index) => (
                <li
                  className={styles.endpointItem}
                  key={endpoint.targetId ?? endpoint.requestId ?? `${endpoint.endpoint}-${index}`}
                >
                  <div className={styles.endpointTopline}>
                    <span className={styles.methodBadge}>{endpoint.method}</span>
                    <span className={styles.endpointState}>Seleccionado</span>
                  </div>
                  <code className={styles.endpointUrl}>{endpoint.endpoint}</code>
                  <div className={styles.endpointMeta}>
                    {endpoint.reason && <span>{endpoint.reason}</span>}
                    {endpoint.recommendedTool && (
                      <span>
                        Herramienta <strong>{endpoint.recommendedTool}</strong>
                      </span>
                    )}
                    {endpoint.targetId && <span>ID {endpoint.targetId}</span>}
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <p className={styles.emptyState}>
              {isFinished
                ? "El reconocimiento no identificó endpoints prioritarios."
                : "Los endpoints priorizados aparecerán al terminar el reconocimiento."}
            </p>
          )}
        </section>

        <section className={`${styles.panelCard} ${styles.vulnerabilitiesCard}`}>
          <div className={styles.sectionHeading}>
            <div>
              <p className={styles.eyebrow}>Hallazgos</p>
              <h2 className={styles.sectionTitle}>Vulnerabilidades</h2>
            </div>
            <span className={`${styles.countBadge} ${styles.vulnerabilityCount}`}>
              {vulnerabilities.length}
            </span>
          </div>

          {vulnerabilities.length > 0 && (
            <div className={styles.severitySummary} aria-label="Resumen por severidad">
              {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((severity) => (
                <span
                  className={`${styles.severityChip} ${styles[`severity${severity}`]}`}
                  key={severity}
                >
                  {severity} <strong>{severityCounts[severity] ?? 0}</strong>
                </span>
              ))}
            </div>
          )}

          {vulnerabilities.length > 0 ? (
            <ul className={styles.vulnerabilityList}>
              {vulnerabilities.map((vulnerability, index) => (
                <li
                  className={styles.vulnerabilityItem}
                  key={`${vulnerability.title}-${vulnerability.endpoint ?? index}`}
                >
                  <div className={styles.vulnerabilityTopline}>
                    <span
                      className={`${styles.severityBadge} ${
                        styles[`severity${vulnerability.severity}`]
                      }`}
                    >
                      {vulnerability.severity}
                    </span>
                    {vulnerability.confidence && (
                      <span className={styles.confidence}>
                        Confianza {vulnerability.confidence}
                      </span>
                    )}
                  </div>
                  <h3 className={styles.vulnerabilityTitle}>{vulnerability.title}</h3>
                  {vulnerability.endpoint && (
                    <code className={styles.endpointUrl}>{vulnerability.endpoint}</code>
                  )}
                  {vulnerability.evidence && (
                    <p className={styles.evidence}>{vulnerability.evidence}</p>
                  )}
                  <div className={styles.vulnerabilityFooter}>
                    {vulnerability.toolsUsed && vulnerability.toolsUsed.length > 0 && (
                      <span>Herramientas: {vulnerability.toolsUsed.join(", ")}</span>
                    )}
                    {vulnerability.pocScript && (
                      <details className={styles.pocDetails}>
                        <summary>Ver prueba</summary>
                        <pre>{vulnerability.pocScript}</pre>
                      </details>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className={styles.emptyState}>
              {isFinished
                ? "La validación terminó sin vulnerabilidades confirmadas."
                : "Los hallazgos confirmados aparecerán aquí durante la validación."}
            </p>
          )}
        </section>
      </div>

      <section className={`${styles.panelCard} ${styles.reportCard}`}>
        <div className={styles.reportHeader}>
          <div>
            <p className={styles.eyebrow}>Resultado de la auditoría</p>
            <h2 className={styles.sectionTitle}>Reporte final</h2>
          </div>
          {finalReport && <span className={styles.reportReady}>Informe generado</span>}
        </div>
        {finalReport ? (
          <MarkdownReport report={finalReport} />
        ) : (
          <p className={styles.emptyState}>
            El informe se mostrará aquí cuando termine la generación del reporte.
          </p>
        )}
      </section>
    </div>
  );
};
