"use client";

import { useState } from "react";
import {
  Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import styles from "./AuditReport.module.css";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface AuditFinding {
  id?: string;
  title: string;
  severity: Severity;
  type: string;
  cwe?: string;
  tool?: string;
  endpoint?: string;
  evidence?: string;
  command?: string;
}

export interface AuditReportData {
  taskId: string;
  target: string;
  modalidad: string;
  date?: string;
  summary: {
    totalObjectives: number | null;
    objectivesLabel?: string;
    totalFindings: number;
    severity: Record<"HIGH" | "MEDIUM" | "LOW", number> & Partial<Record<"CRITICAL" | "INFO", number>>;
    activeConfirmations: number | null;
  };
  findings: AuditFinding[];
  partial?: boolean;
}

export const mockData: AuditReportData = {
  taskId: "196daf0b-d60b-412c-9f2e-a0cbea66a29e",
  target: "http://weak-page:3009",
  modalidad: "bac_default",
  summary: {
    totalObjectives: 39,
    totalFindings: 6,
    severity: { HIGH: 6, MEDIUM: 0, LOW: 0 },
    activeConfirmations: 6,
  },
  findings: [
    {
      id: "BAC-ROLE-ADMIN-001",
      title: "Missing Role Check on Admin",
      severity: "HIGH",
      type: "Broken Access Control",
      cwe: "CWE-285",
      tool: "access_control_prober",
      endpoint: "http://weak-page:3009/api/admin/vulnerabilities",
      evidence: "El token de atacante accedió exitosamente a la ruta de admin.",
      command: "curl -s -H 'Authorization: Bearer $ATTACKER_TOKEN' http://weak-page:3009/api/admin/vulnerabilities",
    },
    {
      id: "BAC-MASS-ASSIGN-001",
      title: "Mass Assignment in Registration",
      severity: "HIGH",
      type: "Broken Access Control",
      cwe: "CWE-915",
      tool: "access_control_prober",
      endpoint: "http://weak-page:3009/api/auth/register",
      evidence: "El registro aceptó la creación de un usuario con 'role: admin'.",
      command: "curl -s -H 'Authorization: Bearer $ATTACKER_TOKEN' http://weak-page:3009/api/auth/register",
    },
    {
      id: "BAC-AUTH-ME-001",
      title: "Missing Authentication (/api/me)",
      severity: "HIGH",
      type: "Broken Access Control",
      cwe: "CWE-306",
      tool: "access_control_prober",
      endpoint: "http://weak-page:3009/api/me",
      evidence: "El endpoint /api/me responde 200 OK sin proporcionar token de autenticación.",
      command: "curl -s -H 'Authorization: Bearer $ATTACKER_TOKEN' http://weak-page:3009/api/me",
    },
  ],
};

const severityColors: Record<Severity, string> = {
  CRITICAL: "#7C3AED",
  HIGH: "#EF4444",
  MEDIUM: "#F59E0B",
  LOW: "#3B82F6",
  INFO: "#64748B",
};

const severities: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function formatEndpointLabel(endpoint: string): string {
  const label = endpoint.replace(/^https?:\/\/[^/]+(?=\/)/i, "");
  return label.length > 18 ? `${label.slice(0, 17)}…` : label;
}

export default function AuditReport({ report }: { report: AuditReportData }) {
  const [copyStatus, setCopyStatus] = useState<{ index: number; message: string } | null>(null);
  const severityData = severities.filter((severity) =>
    severity === "HIGH" || severity === "MEDIUM" || severity === "LOW" || (report.summary.severity[severity] ?? 0) > 0
  ).map((severity) => ({
    name: severity,
    value: report.summary.severity[severity] ?? 0,
    color: severityColors[severity],
  }));
  const severityTotal = severityData.reduce((total, item) => total + item.value, 0);
  const countsByEndpoint = new Map<string, number>();
  for (const finding of report.findings) {
    const endpoint = finding.endpoint || "Sin endpoint";
    countsByEndpoint.set(endpoint, (countsByEndpoint.get(endpoint) ?? 0) + 1);
  }
  const endpointData = Array.from(countsByEndpoint, ([name, value]) => ({ name, value }));

  const copyCommand = async (command: string, index: number) => {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Portapapeles no disponible");
      }
      await navigator.clipboard.writeText(command);
      setCopyStatus({ index, message: "Comando copiado." });
    } catch {
      setCopyStatus({ index, message: "No se pudo copiar. Selecciona el comando y cópialo manualmente." });
    }
  };

  return (
    <article className={styles.report}>
      <header className={styles.header}>
        <p className={styles.eyebrow}>SECURE · Auditoría</p>
        <h1>Reporte de Auditoría de Seguridad Web</h1>
        <dl className={styles.metadata}>
          <div><dt>ID de Tarea</dt><dd>{report.taskId}</dd></div>
          <div><dt>Objetivo</dt><dd>{report.target}</dd></div>
          <div><dt>Fecha</dt><dd>{report.date || "No disponible"}</dd></div>
        </dl>
      </header>

      {report.partial && <p className={styles.notice}>El escaneo terminó con resultados parciales.</p>}

      <section className={styles.kpis} aria-label="Resumen de auditoría">
        <div className={styles.card}><p>Total Hallazgos</p><strong>{report.summary.totalFindings}</strong></div>
        <div className={styles.card}><p>Confirmados Activos</p><strong>{report.summary.activeConfirmations ?? "No disponible"}</strong></div>
        <div className={styles.card}><p>{report.summary.objectivesLabel ?? "Objetivos Auditados"}</p><strong>{report.summary.totalObjectives ?? "No disponible"}</strong></div>
      </section>

      <div className={styles.charts}>
        <section className={`${styles.card} ${styles.chartCard}`} aria-labelledby="audit-severity-title">
          <h2 id="audit-severity-title">Distribución por severidad</h2>
          <p>Distribución por severidad reportada</p>
          {severityTotal > 0 ? (
            <div className={styles.chart} aria-hidden="true">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={severityData} dataKey="value" nameKey="name" innerRadius="58%" outerRadius="82%" paddingAngle={2}>
                    {severityData.map((item) => <Cell key={item.name} fill={item.color} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : <p className={styles.emptyChart}>No hay severidades registradas.</p>}
          <ul className={styles.legend}>
            {severityData.map((item) => (
              <li key={item.name}>
                <span className={`${styles.dot} ${styles[item.name]}`} aria-hidden="true" />
                <span>{item.name}</span><strong>{item.value}</strong>
              </li>
            ))}
          </ul>
        </section>

        <section className={`${styles.card} ${styles.chartCard}`} aria-labelledby="audit-endpoint-title">
          <h2 id="audit-endpoint-title">Hallazgos por endpoint</h2>
          <p>Conteo de los hallazgos incluidos en la lista</p>
          {endpointData.length > 0 ? (
            <div className={styles.chart} style={{ height: Math.max(240, endpointData.length * 38 + 50) }} aria-hidden="true">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={endpointData} layout="vertical" margin={{ top: 12, right: 12, left: 0, bottom: 8 }}>
                  <CartesianGrid stroke="#E5E7EB" strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" allowDecimals={false} axisLine={false} tickLine={false} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={130}
                    interval={0}
                    tick={{ fontSize: 11 }}
                    tickFormatter={formatEndpointLabel}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip />
                  <Bar dataKey="value" name="Hallazgos" fill="#6D28D9" radius={[0, 6, 6, 0]} maxBarSize={40} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : <p className={styles.emptyChart}>No hay hallazgos para mostrar.</p>}
          <ul className={styles.legend}>
            {endpointData.map((item) => <li key={item.name}><span>{item.name}</span><strong>{item.value}</strong></li>)}
          </ul>
        </section>
      </div>

      <section className={styles.findings} aria-labelledby="audit-findings-title">
        <div className={styles.sectionHeading}>
          <div>
            <h2 id="audit-findings-title">Hallazgos</h2>
            <p>Detalle de los resultados incluidos en el reporte</p>
          </div>
          <span className={styles.count}>{report.findings.length}</span>
        </div>
        {report.findings.length !== report.summary.totalFindings && (
          <p className={styles.notice}>
            El resumen indica {report.summary.totalFindings} hallazgos; la lista recibida contiene {report.findings.length}.
          </p>
        )}
        {report.findings.length === 0 && <p className={styles.emptyChart}>No hay hallazgos para mostrar.</p>}
        {report.findings.map((finding, index) => (
          <article className={`${styles.card} ${styles.finding}`} key={`${finding.id ?? finding.title}-${index}`}>
            <div className={styles.findingHeader}>
              <h3>{finding.title}</h3>
              <span className={`${styles.badge} ${styles[finding.severity]}`}>{finding.severity}</span>
            </div>
            <dl className={styles.findingMeta}>
              <div><dt>ID</dt><dd>{finding.id || "No disponible"}</dd></div>
              <div><dt>Tipo (CWE)</dt><dd>{finding.type}{finding.cwe ? ` · ${finding.cwe}` : ""}</dd></div>
              <div><dt>Tool</dt><dd>{finding.tool || "No disponible"}</dd></div>
              <div><dt>Endpoint</dt><dd>{finding.endpoint || "No disponible"}</dd></div>
            </dl>
            <div className={styles.evidence}>
              <span className={styles.infoIcon} aria-hidden="true">i</span>
              <div><strong>Evidencia</strong><p>{finding.evidence || "No disponible"}</p></div>
            </div>
            {finding.command && <div className={styles.codeBlock}>
              <div className={styles.codeHeader}>
                <span>Comando</span>
                <button type="button" onClick={() => { if (finding.command) void copyCommand(finding.command, index); }} aria-label={`Copiar comando de ${finding.title}`}>
                  Copiar
                </button>
              </div>
              <pre><code>{finding.command}</code></pre>
            </div>}
            <p className={styles.copyStatus} role="status">
              {copyStatus?.index === index ? copyStatus.message : ""}
            </p>
          </article>
        ))}
      </section>
    </article>
  );
}
