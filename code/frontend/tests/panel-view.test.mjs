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
