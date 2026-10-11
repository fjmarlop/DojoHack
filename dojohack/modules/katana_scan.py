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
"""

import json
import subprocess


def run(target: str) -> list[dict]:
    """Devuelve una lista de hallazgos, uno por endpoint descubierto,
    con el mismo convenio que el resto de módulos: {"name", "detail",
    "severity"}. El timeout lo controla dojohack.timeouts.run_module,
    no esta función."""
    url = f"http://{target}"
    proc = subprocess.run(
        [
            "katana", "-u", url,
            "-jsonl", "-silent", "-jc", "-kf", "all",
        ],
        capture_output=True, text=True,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"katana devolvió código {proc.returncode}: {proc.stderr[:300]}")

    findings = []
    for line in proc.stdout.splitlines():
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
