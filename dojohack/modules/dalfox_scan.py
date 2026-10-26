"""
Módulo dalfox — escáner de XSS. Igual que el resto: binario externo,
cero lógica propia de detección que reescribir en clean-room.

A diferencia de nmap/nuclei/ffuf/katana, dalfox no rastrea el sitio
por su cuenta: solo analiza los parámetros (query string + mining del
HTML/DOM) de las URLs que se le dan. Por eso recibe la lista de
endpoints que katana ya encontró (decisión tomada con Paco: acoplar
estos dos módulos en cli.py, en vez de que dalfox mire solo la URL
raíz del target y se le escapen páginas con formularios en rutas que
no son la raíz — como pasaba en este mismo lab con llevar.php).

Si no se pasan urls (katana falló/se omitió, o no encontró nada), se
cae a probar solo la URL raíz de web_target — peor cobertura, pero
mejor que no ejecutar nada. Recibe un dojohack.web_targets.WebTarget
para ese caso de fallback (ver ffuf_scan.py para el porqué); las urls
de katana ya vienen completas, así que no necesitan web_target.

Usa -f json (un único objeto JSON con todo el scan) en vez de la
salida de consola — mismo motivo que el resto: formato estable entre
versiones.

--workers/--max-concurrent-targets subidos de 50 (su propio defecto,
ya no tan bajo) a 100, y --skip-waf-probe para no gastar peticiones
detectando un WAF que no existe en un lab de práctica — sin esto,
contra una app WordPress real con decenas de URLs y cientos de
parámetros (ARJUN) de por medio, dalfox se comía el timeout del
módulo (ver conversación con Paco, 2026-10-20).

--max-payloads-per-param 300 (su propio defecto es un tope interno de
3000 por parámetro): confirmado con --dry-run contra aceituno.thl que
el grueso de esos 3000 son variantes de bypass de WAF, no payloads
"normales" distintos — con 12 parámetros reales encontrados (mining
de dalfox incluido), el total pasaba de 78.000 peticiones estimadas a
600s de timeout. A 300, el total baja a ~8.400 (una fracción de la
cobertura exhaustiva, pero esos primeros payloads del catálogo son
los que de verdad importan sin WAF que esquivar) — ver conversación
con Paco, 2026-10-26/27.
"""

import json
import tempfile
from pathlib import Path

from .. import subprocess_utils


def run(web_target, urls: list[str] | None = None, timeout: int | None = None) -> list[dict]:
    """Devuelve una lista de hallazgos, uno por XSS detectado, con el
    mismo convenio que el resto de módulos: {"name", "detail",
    "severity"}. `timeout` se propaga a subprocess_utils.run() — cli.py
    lo lanza en paralelo con arjun (ambos solo necesitan katana_urls)
    vía timeouts.run_threadsafe, que necesita un timeout seguro entre
    hilos (ver ese módulo)."""
    urls = urls or [f"{web_target.base_url}/"]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(urls))
        urls_path = tmp.name

    try:
        proc = subprocess_utils.run(
            [
                "dalfox", "scan", urls_path, "-f", "json", "--silence",
                "--workers", "100", "--max-concurrent-targets", "100",
                "--skip-waf-probe", "--max-payloads-per-param", "300",
            ],
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"dalfox devolvió código {proc.returncode}: {proc.stderr[:300]}")

        data = json.loads(proc.stdout)
    finally:
        Path(urls_path).unlink(missing_ok=True)

    findings = []
    for item in data.get("findings", []):
        param = item.get("param", "?")
        method = item.get("method", "GET")
        severity = item.get("severity", "info").lower()
        payload = item.get("payload", "")
        poc_url = item.get("data", "")
        tipo = item.get("type", "?")  # V=Verified (ejecución confirmada), R=Reflected (sin confirmar), A=AST DOM, I=informativo

        detalle = f"{method} param '{param}' (tipo {tipo}) — payload: {payload} — {poc_url}"
        findings.append({"name": "DALFOX", "detail": detalle, "severity": severity})

    return findings
