import { request } from "./apiClient.js";

const getToken = () =>
  JSON.parse(localStorage.getItem("dulceNube_session") || "null")?.token || null;

export async function getVulnerabilities() {
  return request("/admin/vulnerabilities", { token: getToken() });
}

export async function toggleVulnerability(flag, value) {
  return request("/admin/vulnerabilities", {
    method: "POST",
    body: { flag, value },
    token: getToken()
  });
}

export async function setAllVulnerabilities(value) {
  return request("/admin/vulnerabilities", {
    method: "POST",
    body: { all: true, value },
    token: getToken()
  });
}