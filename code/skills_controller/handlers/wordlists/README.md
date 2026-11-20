# Wordlists para JWT brute force

## `jwt.secrets.list`

**Fuente:** https://github.com/wallarm/jwt-secrets
**Autor:** Wallarm (https://wallarm.com)
**Licencia:** MIT — ver texto completo abajo
**Fecha de descarga:** 2026-11-17
**Uso en este proyecto:** brute force de secretos HMAC débiles en el
handler `jwt_tool_handler.py`, con fines exclusivamente educativos y
de auditoría de seguridad autorizada.

### Formato

Un secreto por línea. Sin comentarios, sin cabeceras. Compatible con:

- `hashcat -a 0 -m 16500 <jwt> jwt.secrets.list`
- `jwt_tool`
- La función `load_wordlist()` del handler

### Cómo añadir más wordlists

1. Guarda el nuevo archivo en esta carpeta.
2. Añade su ruta a `WORDLIST_CANDIDATES` en `jwt_tool_handler.py`.
3. Documenta su fuente, autor y licencia en este README.

---

## Licencia MIT (texto completo del proyecto original)

MIT License

Copyright (c) 2020 Wallarm

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.