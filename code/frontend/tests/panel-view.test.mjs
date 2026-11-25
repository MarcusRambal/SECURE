import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Module, { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";

const require = createRequire(import.meta.url);
require.extensions[".css"] = (module) => {
  module.exports = new Proxy({}, {
    get: (_, property) => property === "__esModule" ? false : property,
  });
};
for (const extension of [".ts", ".tsx"]) {
  require.extensions[extension] = (module, filename) => {
    module._compile(ts.transpileModule(readFileSync(filename, "utf8"), {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        jsx: ts.JsxEmit.ReactJSX,
        esModuleInterop: true,
      },
    }).outputText, filename);
  };
}

const componentPath = resolve(dirname(fileURLToPath(import.meta.url)), "../components/dashboard/PanelView.tsx");
const componentModule = new Module(componentPath);
componentModule.filename = componentPath;
componentModule.paths = Module._nodeModulePaths(dirname(componentPath));
componentModule._compile(
  ts.transpileModule(readFileSync(componentPath, "utf8"), {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      jsx: ts.JsxEmit.ReactJSX,
      esModuleInterop: true,
    },
  }).outputText,
  componentPath,
);
const { PanelView } = componentModule.exports;

const renderPanel = (vulnerabilities, finalReport) =>
  renderToStaticMarkup(
    React.createElement(PanelView, {
      taskId: "test",
      events: [],
      vulnerabilities,
      finalReport,
      isConnected: true,
      isFinished: true,
      isFailed: false,
    }),
  );

test("groups critical findings with high without changing the original data or report", () => {
  const vulnerabilities = [
    { title: "Critical finding", severity: "CRITICAL" },
    { title: "High finding", severity: "HIGH" },
    { title: "Medium finding", severity: "MEDIUM" },
    { title: "Low finding", severity: "LOW" },
    { title: "Informational finding", severity: "INFO" },
  ];
  const html = renderPanel(vulnerabilities, "Reporte original: CRITICAL");
  const summary = html.match(/<div class="severitySummary"[^>]*>(.*?)<\/div>/)?.[1];
  assert.ok(summary);
  assert.match(summary, /HIGH <strong>2<\/strong>/);
  assert.match(summary, /MEDIUM <strong>1<\/strong>/);
  assert.match(summary, /LOW <strong>1<\/strong>/);
  assert.doesNotMatch(summary, /CRITICAL|INFO/);
  assert.equal((html.match(/class="severityBadge severityHIGH">HIGH<\/span>/g) ?? []).length, 2);
  assert.match(html, /Critical finding/);
  assert.doesNotMatch(html, /Informational finding/);
  assert.match(html, /Reporte original: CRITICAL/);
  assert.equal(vulnerabilities[0].severity, "CRITICAL");
});

test("preserves the empty state when only informational findings are present", () => {
  const html = renderPanel([{ title: "Info", severity: "INFO" }]);
  assert.doesNotMatch(html, /severitySummary|severityBadge/);
  assert.match(html, /La validación terminó sin vulnerabilidades confirmadas/);
});

test("shows XSS evidence without a redundant verification section", () => {
  const html = renderPanel([
    {
      title: "Reflected DOM Cross-Site Scripting (XSS)",
      severity: "HIGH",
      evidence: "Chromium confirmó la prueba: <img onerror=proof>",
      verificationSteps: "Pasos XSS",
    },
    {
      title: "SQL Injection",
      severity: "HIGH",
      verificationSteps: "Pasos SQL",
    },
  ]);
  assert.match(html, /Chromium confirmó la prueba: &lt;img onerror=proof&gt;/);
  assert.doesNotMatch(html, /Pasos XSS/);
  assert.equal((html.match(/Cómo verificar/g) ?? []).length, 1);
  assert.match(html, /Pasos SQL/);
});

test("renders SQLi table evidence with extracted preview values", () => {
  const html = renderPanel([
    {
      title: "SQL Injection",
      severity: "HIGH",
      tableEvidence: [{
        database: "SQLite",
        table: "users",
        rowCount: 1,
        truncated: false,
        columns: ["email", "password"],
        preview: [["alice@example.test", "plaintext-secret"]],
        status: "retrieved",
        valuesRedacted: false,
      }],
    },
  ]);
  assert.match(html, /Evidencia de tablas/);
  assert.match(html, /SQLite\.users/);
  assert.match(html, /1 filas/);
  assert.match(html, /<th[^>]*>email<\/th>/);
  assert.match(html, /<th[^>]*>password<\/th>/);
  assert.match(html, /alice@example\.test/);
  assert.match(html, /plaintext-secret/);
  assert.match(html, /Muestra de 1 fila recuperada por SQLMap/);
});

test("renders all five SQLi evidence rows", () => {
  const html = renderPanel([{
    title: "SQL Injection",
    severity: "HIGH",
    tableEvidence: [{
      table: "users",
      rowCount: 5,
      columns: ["email"],
      preview: Array.from({ length: 5 }, (_, i) => [`user${i + 1}@example.test`]),
    }],
  }]);

  assert.match(html, /user5@example\.test/);
  assert.match(html, /Muestra de 5 filas recuperadas por SQLMap/);
});

test("renders report paragraphs, warnings and tables as separate blocks", () => {
  const report = [
    "# Informe",
    "",
    "**Tarea:** `123`",
    "",
    "**Objetivo:** `https://example.test`",
    "",
    "> **Advertencia:** Análisis parcial.",
    "",
    "| Herramienta | Total |",
    "|---|---:|",
    "| `browserXssValidator` | 2 |",
  ].join("\n");
  const html = renderPanel([], report);
  assert.match(html, /<p><strong>Tarea:<\/strong> <code>123<\/code><\/p>/);
  assert.match(html, /<p><strong>Objetivo:<\/strong>/);
  assert.match(html, /<blockquote[^>]*><strong>Advertencia:<\/strong> Análisis parcial\.<\/blockquote>/);
  assert.match(html, /<table/);
  assert.match(html, /<th[^>]*>Herramienta<\/th>/);
  assert.match(html, /<td><code>browserXssValidator<\/code><\/td>/);
  assert.doesNotMatch(html, /\|---/);
});

test("keeps literal pipes and the content after a table", () => {
  const report = [
    "Herramienta | Detalle",
    "--- | ---",
    "`browser|validator` | valor\\|observado",
    "",
    "Conclusión independiente.",
  ].join("\n");
  const html = renderPanel([], report);
  assert.match(html, /<td><code>browser\|validator<\/code><\/td>/);
  assert.match(html, /<td>valor\|observado<\/td>/);
  assert.match(html, /<p>Conclusión independiente\.<\/p>/);
});

test("renders the real completed scan in the audit report without mock data", () => {
  const taskId = "real-task";
  const finding = {
    title: "Control de acceso",
    severity: "CRITICAL",
    findingId: "REAL-001",
    cwe: "CWE-285",
    endpoint: "https://example.test/admin",
    evidence: "Evidencia real",
    toolsUsed: ["access_control_prober"],
    pocScript: "curl https://example.test/admin",
    attackDemonstrated: "active_access_control_exploitation",
  };
  const events = [
    { eventType: "TOOL_EXECUTION", agentName: "recon", payload: { message: "Recon", details: { status: "SUCCESS", endpointsCount: 2 } } },
    { eventType: "VULN_DETECTED", agentName: "validate", payload: { message: "Vulnerabilidad", vulnerability: finding } },
    { eventType: "TOOL_EXECUTION", agentName: "validate", payload: { message: "Validación", details: { status: "SUCCESS", vulnerabilitiesCount: 1 } } },
    { eventType: "SCAN_COMPLETE", agentName: "orquestador", timestamp: "2026-11-25T18:00:00Z", payload: { message: "Completado", details: { status: "COMPLETED" } } },
  ];
  const html = renderToStaticMarkup(React.createElement(PanelView, {
    taskId, targetUrl: "https://example.test", attackType: "bac_default", events,
    vulnerabilities: [finding], finalReport: "Informe original", isConnected: false, isFinished: true, isFailed: false,
  }));
  assert.match(html, /Reporte de Auditoría de Seguridad Web/);
  assert.match(html, /Objetivos priorizados<\/p><strong>2<\/strong>/);
  assert.match(html, /Confirmados Activos<\/p><strong>1<\/strong>/);
  assert.match(html, /REAL-001/);
  assert.match(html, /CWE-285/);
  assert.match(html, /curl https:\/\/example.test\/admin/);
  assert.match(html, /2026-11-25T18:00:00Z/);
  assert.match(html, /Informe original/);
  assert.doesNotMatch(html, /BAC-ROLE-ADMIN-001/);
});

test("does not display the report during a scan or invent unavailable fields", () => {
  const finding = { title: "Hallazgo", severity: "INFO", endpoint: "https://example.test/a" };
  const events = [
    { eventType: "VULN_DETECTED", agentName: "validate", payload: { message: "Vulnerabilidad", vulnerability: finding } },
    { eventType: "TOOL_EXECUTION", agentName: "validate", payload: { message: "Validación", details: { status: "PARTIAL", vulnerabilitiesCount: 2 } } },
  ];
  const props = {
    taskId: "real-task", targetUrl: "https://example.test", attackType: "xss", events,
    vulnerabilities: [finding], isConnected: true, isFinished: false, isFailed: false,
  };
  assert.doesNotMatch(renderToStaticMarkup(React.createElement(PanelView, props)), /Reporte de Auditoría de Seguridad Web/);
  const completedEvents = [...events, { eventType: "SCAN_COMPLETE", agentName: "orquestador", timestamp: "2026-11-25", payload: { message: "Terminado", details: { status: "PARTIAL" } } }];
  const html = renderToStaticMarkup(React.createElement(PanelView, { ...props, events: completedEvents, isFinished: true }));
  assert.match(html, /resultados parciales/);
  assert.match(html, /El resumen indica 2 hallazgos; la lista recibida contiene 1/);
  assert.match(html, /Confirmados Activos<\/p><strong>No disponible<\/strong>/);
  assert.match(html, /Objetivos priorizados<\/p><strong>No disponible<\/strong>/);
  assert.match(html, /class="badge INFO">INFO/);
  assert.doesNotMatch(html, /Copiar comando de Hallazgo/);
});
