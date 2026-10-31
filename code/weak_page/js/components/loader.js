export function loader(label = "Cargando...") {
  return `<div class="loader" role="status"><div class="loader-inner"><span class="spinner"></span><span>${label}</span></div></div>`;
}
