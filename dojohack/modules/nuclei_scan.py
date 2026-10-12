"""
Módulo nuclei — igual que nmap_scan.py: binario externo, cero lógica
propia de detección que reescribir en clean-room. Nuclei ya trae un
arsenal enorme de plantillas; no se le pasa ningún filtro de tags para
no recortarlo — coherente con la decisión de "arsenal completo, sin
recortar por tratarse de CTF" (ver CLAUDE.md).

Usa -jsonl (una línea JSON por hallazgo) en vez de parsear la salida
de consola — mismo motivo que nmap con -oX: formato estable entre
versiones en vez de fiarse del formato de impresión, que trae colores
y barras de progreso pensadas para humanos, no para parsear.
"""

import json

from .. import subprocess_utils


def run(target: str) -> list[dict]:
    """Devuelve una lista de hallazgos, uno por plantilla que ha
    matcheado, con el mismo convenio que el resto de módulos:
    {"name", "detail", "severity"}. El timeout lo controla
    dojohack.timeouts.run_module, no esta función."""
    proc = subprocess_utils.run(
        ["nuclei", "-target", target, "-jsonl", "-silent", "-no-color"],
        text=True,
    )
    # A diferencia de nmap, un código de salida != 0 en nuclei no
    # siempre significa fallo (p.ej. puede devolver distinto de 0 por
    # avisos de templates sin dejar de escanear) — solo se trata como
    # error real si además no hay nada de stdout que parsear.
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"nuclei devolvió código {proc.returncode}: {proc.stderr[:300]}")

    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = item.get("info", {})
        template_id = item.get("template-id", "desconocido")
        name = info.get("name", template_id)
        severity = info.get("severity", "info")
        matched_at = item.get("matched-at") or item.get("host", target)

        detalle = f"{name} [{template_id}] en {matched_at}"
        findings.append({"name": "NUCLEI", "detail": detalle, "severity": severity})

    return findings
