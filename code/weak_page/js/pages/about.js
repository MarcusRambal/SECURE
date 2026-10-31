const team = [
  { name: "Camila Reyes", role: "Fundadora y pastelera", image: "photo-1580489944761-15a19d654956" },
  { name: "Valeria Cruz", role: "Maestra panadera", image: "photo-1551836022-d5d88e9218df" },
  { name: "Mateo Silva", role: "Decoración y diseño", image: "photo-1500648767791-00dcc994a43e" }
];

export function renderAbout() {
  return `<main>
    <section class="container about-hero"><div><span class="eyebrow">Nuestra historia</span><h1>Un sueño que sabe a hogar</h1><p class="muted">Dulce Nube nació en 2018 con una receta familiar, un horno pequeño y una idea sencilla: que cada persona merece un momento bonito, aunque sea un martes cualquiera.</p><p class="muted">Hoy seguimos horneando en lotes pequeños, con ingredientes de temporada y las mismas manos curiosas de siempre. Porque creemos que la magia está en hacer las cosas con tiempo y con cariño.</p><a class="button" href="#/catalog">Prueba algo hecho por nosotras</a></div><img src="https://images.unsplash.com/photo-1556911220-bff31c812dba?auto=format&fit=crop&w=1000&q=85" alt="Pastel artesanal preparado en una cocina luminosa" /></section>
    <section class="section soft-section"><div class="container"><div class="section-heading"><span class="eyebrow">Lo que nos mueve</span><h2>Hecho con intención</h2></div>
      <div class="values-grid"><article class="value-card"><span class="value-icon">🌿</span><h3>Misión</h3><p class="muted">Crear momentos felices con repostería honesta, artesanal y hecha para compartir.</p></article><article class="value-card"><span class="value-icon">☁️</span><h3>Visión</h3><p class="muted">Ser ese lugar cercano al que vuelves por el sabor, pero también por cómo te hace sentir.</p></article><article class="value-card"><span class="value-icon">🤎</span><h3>Valores</h3><p class="muted">Cuidado en cada detalle, ingredientes de calidad, comunidad y alegría sin prisas.</p></article></div>
    </div></section>
    <section class="section"><div class="container"><div class="section-heading"><span class="eyebrow">El equipo detrás del glaseado</span><h2>Manos y corazones</h2><p class="muted">Personas reales, mucho café y harina en el delantal.</p></div>
      <div class="team-grid">${team.map(person => `<article class="team-card"><img src="https://images.unsplash.com/${person.image}?auto=format&fit=crop&w=700&q=80" alt="Retrato de ${person.name}" loading="lazy" /><div><h3>${person.name}</h3><p class="muted">${person.role}</p></div></article>`).join("")}</div>
    </div></section>
    <section class="section"><div class="container"><div class="cta-panel"><h2>¿Nos dejas endulzar tu próximo momento?</h2><a class="button" href="#/contact">Cuéntanos qué celebras</a></div></div></section>
  </main>`;
}

export function bindAbout() {}
