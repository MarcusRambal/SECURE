export const CONFIG = {
  API_MODE: "api", // "mock" | "api"
  API_BASE_URL: window.location.port === "3008"
    ? `${window.location.protocol}//${window.location.hostname}:3009/api`
    : `${window.location.origin}/api`
};
