"""
Módulo testssl — configuración TLS/SSL (cifrados débiles, protocolos
obsoletos, certificado, vulnerabilidades conocidas como Heartbleed/
ROBOT/CCS...). Igual que el resto: binario externo, cero lógica propia
de detección que reescribir en clean-room.

Solo tiene sentido contra un target https — cli.py lo gatea así
(web_target.scheme == "https"), no se lanza contra http plano.

LIMITACIÓN CONOCIDA: el formato del JSON (data["scanResult"] es una
lista; cada entrada trae secciones como "protocols", "ciphers",
"vulnerabilities", "headerResponse"..., cada una una lista de
{"id","severity","finding",...}) se validó contra un servidor HTTPS
autofirmado local (Python + openssl, generado solo para esta prueba),
no contra un lab de CTF real todavía — ninguno de los disponibles
hasta ahora expone HTTPS. El parseo en sí no debería depender de eso
(es genérico por sección), pero queda pendiente confirmarlo contra un
target real en cuanto aparezca uno.

Se descartan las entradas con severity "OK" (test pasado, sin nada que
reportar — mismo principio que nmap solo reporta puertos abiertos, no
cerrados); el resto (INFO/LOW/MEDIUM/HIGH/CRITICAL) se reporta tal
cual, de todas las secciones, sin recortar ninguna.
"""

import json
import tempfile
from pathlib import Path

from .. import subprocess_utils

_CLAVES_METADATO = {"targetHost", "ip", "port", "rDNS", "service"}
_SEVERITY_MAP = {
    "CRITICAL": "critical", "FATAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium", "WARN": "medium",
    "LOW": "low",
    "INFO": "info",
}


def run(web_target, timeout: int | None = None) -> list[dict]:
    """Devuelve una lista de hallazgos con el mismo convenio que el
    resto de módulos: {"name", "detail", "severity"}. `timeout` se
    propaga a subprocess_utils.run() — cli.py lo lanza en paralelo con
    otros módulos independientes vía timeouts.run_threadsafe (ver ese
    módulo para el porqué)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = Path(tmp.name)

    try:
        proc = subprocess_utils.run(
            [
                "testssl", "--quiet", "--color", "0",
                "--jsonfile-pretty", str(out_path),
                f"{web_target.host}:{web_target.port}",
            ],
            text=True,
            timeout=timeout,
        )
        if not out_path.is_file() or out_path.stat().st_size == 0:
            if proc.returncode != 0:
                raise RuntimeError(f"testssl devolvió código {proc.returncode}: {proc.stderr[:300]}")
            return []
        data = json.loads(out_path.read_text(encoding="utf-8"))
    finally:
        out_path.unlink(missing_ok=True)

    findings = []
    for target_result in data.get("scanResult", []):
        for seccion, items in target_result.items():
            if seccion in _CLAVES_METADATO or not isinstance(items, list):
                continue
            for item in items:
                severity_raw = (item.get("severity") or "").upper()
                if severity_raw in ("OK", ""):
                    continue
                detalle = f"{item.get('id', seccion)}: {item.get('finding', '')}"
                if item.get("cve"):
                    detalle += f" (CVE: {item['cve']})"
                findings.append({
                    "name": "TESTSSL",
                    "detail": detalle[:300],
                    "severity": _SEVERITY_MAP.get(severity_raw, "info"),
                })

    return findings
