"""
Módulo katana — crawler/spider. Igual que el resto: binario externo,
cero lógica propia de detección que reescribir en clean-room.

Complementa a ffuf: ffuf prueba rutas de una wordlist que no sabe si
existen; katana sigue enlaces, formularios y JS reales de las páginas
que sí existen, así que encuentra endpoints que ninguna wordlist
genérica adivinaría (ej. acciones de formulario, rutas enlazadas solo
desde JS).

Flags elegidos:
- -jc (js-crawl): sigue y parsea JS en busca de más endpoints —
  coherente con "arsenal completo, sin recortar".
- -kf all (known-files): también comprueba robots.txt y sitemap.xml.
- -fx (form-extraction): extrae method/action/campos de los
  formularios de cada página — lo necesitan las sondas propias
  (SSTI y las que vengan después) para saber qué campos POST probar,
  no solo los parámetros de query string de las URLs.
- Profundidad por defecto de katana (3) — no se toca; crawl completo
  en un lab local no tarda lo suficiente como para justificar
  reducirla.
- NO se usa -aff (automatic-form-fill): eso envía formularios de
  verdad (POST), lo que puede mutar estado de la app del lab (crear
  pedidos, escribir ficheros...). Rastrear no debería modificar nada;
  probar formularios es otra fase, no esta.

Usa -jsonl (una línea JSON por request) en vez de la salida de
consola — mismo motivo que nmap/nuclei: formato estable entre
versiones.

crawl()/parse_findings() están separados (en vez de un único run())
porque dalfox necesita las mismas URLs que rastrea katana (dalfox no
rastrea el sitio por su cuenta, solo analiza parámetros de las URLs
que se le dan — decisión tomada con Paco). Separarlos permite que
cli.py relance el crawl una sola vez y lo reutilice para ambos
módulos, en vez de que dalfox repita el crawl por su cuenta.

Recibe un dojohack.web_targets.WebTarget, no un target suelto — ver
ffuf_scan.py para el porqué (la app puede no estar en http/80/raíz).
"""

import json

from .. import subprocess_utils


def crawl(web_target, timeout: int | None = None) -> str:
    """Ejecuta katana contra web_target.base_url y devuelve la salida
    cruda en jsonl (una línea JSON por request). `timeout` se propaga
    a subprocess_utils.run() — cli.py lo lanza en paralelo con otros
    módulos independientes vía timeouts.run_threadsafe (ver ese
    módulo para el porqué: signal.SIGALRM no es seguro entre hilos)."""
    url = web_target.base_url
    proc = subprocess_utils.run(
        [
            "katana", "-u", url,
            "-jsonl", "-silent", "-jc", "-kf", "all", "-fx",
        ],
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"katana devolvió código {proc.returncode}: {proc.stderr[:300]}")
    return proc.stdout


def parse_findings(raw_jsonl: str) -> list[dict]:
    """Convierte la salida cruda de crawl() en hallazgos, uno por
    endpoint descubierto, con el mismo convenio que el resto de
    módulos: {"name", "detail", "severity"}."""
    findings = []
    for line in raw_jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        request = item.get("request", {})
        response = item.get("response", {})
        method = request.get("method", "GET")
        endpoint = request.get("endpoint", "")
        status = response.get("status_code")

        detalle = f"{method} {endpoint}"
        if status is not None:
            detalle += f" ({status})"

        findings.append({"name": "KATANA", "detail": detalle, "severity": "info"})

    return findings


def parse_endpoints(raw_jsonl: str) -> list[str]:
    """Convierte la salida cruda de crawl() en una lista de URLs
    únicas descubiertas (sin formatear como hallazgo) — lo que
    necesita dalfox para elegir qué probar."""
    urls = []
    seen = set()
    for line in raw_jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        endpoint = item.get("request", {}).get("endpoint")
        if endpoint and endpoint not in seen:
            seen.add(endpoint)
            urls.append(endpoint)

    return urls


def parse_forms(raw_jsonl: str) -> list[dict]:
    """Convierte la salida cruda de crawl() en la lista de
    formularios encontrados (method/action/parameters), sin
    duplicados. Lo necesitan las sondas propias (dojohack.probes)
    para construir puntos de inyección POST."""
    forms = []
    seen = set()
    for line in raw_jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        for form in item.get("response", {}).get("forms", []):
            key = (form.get("method"), form.get("action"), tuple(form.get("parameters", [])))
            if key in seen:
                continue
            seen.add(key)
            forms.append(form)

    return forms


def run(web_target) -> list[dict]:
    """Atajo para uso aislado del módulo (pruebas manuales, etc.):
    crawl() + parse_findings() en un solo paso, igual que el resto de
    módulos del pipeline. cli.py no usa esta función directamente
    porque necesita reutilizar el crawl crudo para dalfox — ver
    parse_endpoints()."""
    return parse_findings(crawl(web_target))
