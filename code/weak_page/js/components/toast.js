export function showToast(message, type = "success") {
  const region = document.querySelector("#toast-region");
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.setAttribute("role", "status");
  toast.textContent = message;
  region.append(toast);
  window.setTimeout(() => toast.remove(), 3400);
}
