export function renderFooter() {
  return `<footer class="site-footer"><div class="container">
    <div class="footer-grid">
      <div><a href="#/home" class="brand"><span class="brand-mark">☁</span><span>Dulce Nube</span></a><p>Pequeños momentos, grandes antojos. Horneamos con amor cada día.</p></div>
      <div><h3>Explora</h3><div class="footer-links"><a href="#/catalog">Nuestro catálogo</a><a href="#/about">Nuestra historia</a><a href="#/contact">Contacto</a></div></div>
      <div><h3>Visítanos</h3><p>Av. de los Dulces 128<br />Col. Centro, Ciudad de México</p><p>Mar–Dom · 9:00–19:00</p></div>
      <div><h3>Hablemos</h3><p>hola@dulcenube.com<br />+52 55 1234 5678</p><p><a href="#/contact">Instagram · Facebook · Pinterest</a></p></div>
    </div>
    <div class="footer-bottom"><span>© ${new Date().getFullYear()} Dulce Nube. Hecho con cariño.</span><span>Pastelería artesanal · Hecho en México</span></div>
  </div></footer>`;
}
