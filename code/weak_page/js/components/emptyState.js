export function emptyState({ icon = "☁️", title, message, action = "" }) {
  return `<div class="empty-state"><div class="empty-state-icon" aria-hidden="true">${icon}</div><h2>${title}</h2><p class="muted">${message}</p>${action}</div>`;
}
