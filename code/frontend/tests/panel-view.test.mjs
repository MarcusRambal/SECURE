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
