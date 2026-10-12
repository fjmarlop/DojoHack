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
"""

import json
import tempfile
from pathlib import Path

from .. import subprocess_utils


def run(web_target, urls: list[str] | None = None) -> list[dict]:
    """Devuelve una lista de hallazgos, uno por XSS detectado, con el
    mismo convenio que el resto de módulos: {"name", "detail",
    "severity"}. El timeout lo controla dojohack.timeouts.run_module,
    no esta función."""
    urls = urls or [f"{web_target.base_url}/"]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(urls))
        urls_path = tmp.name

    try:
        proc = subprocess_utils.run(
            ["dalfox", "scan", urls_path, "-f", "json", "--silence"],
            text=True,
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
