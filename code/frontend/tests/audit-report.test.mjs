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

const componentPath = resolve(dirname(fileURLToPath(import.meta.url)), "../components/dashboard/AuditReport.tsx");
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
const { default: AuditReport, mockData, formatEndpointLabel } = componentModule.exports;
const renderReport = (report) => renderToStaticMarkup(React.createElement(AuditReport, { report }));

test("displays summary counts without inventing missing findings or a date", () => {
  const html = renderReport(mockData);
  assert.match(html, /Total Hallazgos<\/p><strong>6<\/strong>/);
  assert.match(html, /Confirmados Activos<\/p><strong>6<\/strong>/);
  assert.match(html, /Objetivos Auditados<\/p><strong>39<\/strong>/);
  assert.match(html, /Fecha<\/dt><dd>No disponible<\/dd>/);
  assert.match(html, /El resumen indica 6 hallazgos; la lista recibida contiene 3/);
  assert.match(html, /Hallazgos por endpoint/);
  assert.match(html, /http:\/\/weak-page:3009\/api\/me<\/span><strong>1<\/strong>/);
  assert.equal((html.match(/class="badge HIGH"/g) ?? []).length, 3);
  assert.match(html, /Bearer \$ATTACKER_TOKEN/);
});

test("aggregates supplied endpoints and handles an empty report", () => {
  const findings = [
    { ...mockData.findings[0], id: "one", endpoint: "https://example.test/a", severity: "MEDIUM" },
    { ...mockData.findings[1], id: "two", endpoint: "https://example.test/a", severity: "LOW" },
    { ...mockData.findings[2], id: "three", endpoint: "https://example.test/b", severity: "HIGH" },
  ];
  const html = renderReport({ ...mockData, date: "2026-11-25", findings });
  assert.match(html, /https:\/\/example.test\/a<\/span><strong>2<\/strong>/);
  assert.match(html, /https:\/\/example.test\/b<\/span><strong>1<\/strong>/);
  assert.match(html, /Fecha<\/dt><dd>2026-11-25<\/dd>/);
  assert.match(html, /class="badge MEDIUM">MEDIUM/);
  assert.match(html, /class="badge LOW">LOW/);

  const empty = renderReport({
    ...mockData,
    findings: [],
    summary: { ...mockData.summary, totalFindings: 0, severity: { HIGH: 0, MEDIUM: 0, LOW: 0 } },
  });

  assert.match(empty, /No hay severidades registradas/);
  assert.match(empty, /No hay hallazgos para mostrar/);
  assert.doesNotMatch(empty, /El resumen indica/);
});

test("shows endpoint paths instead of truncating the common host", () => {
  assert.equal(formatEndpointLabel("http://weak-page:3009/api/me"), "/api/me");
  assert.equal(formatEndpointLabel("http://weak-page:3009/api/admin/vulnerabilities"), "/api/admin/vulner…");
  assert.equal(formatEndpointLabel("Sin endpoint"), "Sin endpoint");
});
