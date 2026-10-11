"""
Módulo nmap — el primero del pipeline, deliberadamente el más simple:
es un binario externo, cero lógica propia de detección que reescribir
en clean-room. Sirve para validar el cableado completo (timeout,
feedback en vivo, guardado) antes de sumar el resto de módulos.

Usa -oX - (XML a stdout) en vez de parsear la salida de texto plano —
mucho más fiable entre versiones de nmap que fiarse del formato de
impresión, que cambia entre versiones.
"""

import subprocess
import xml.etree.ElementTree as ET


def run(target: str) -> list[dict]:
    """Devuelve una lista de hallazgos, un elemento por puerto abierto,
    con el mismo convenio que PocketHacker (preprocessor.py):
    {"name", "detail", "severity"}. El timeout lo controla
    dojohack.timeouts.run_module, no esta función."""
    proc = subprocess.run(
        ["nmap", "-Pn", "-sV", "-T4", "-oX", "-", target],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"nmap devolvió código {proc.returncode}: {proc.stderr[:300]}")

    root = ET.fromstring(proc.stdout)
    findings = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        portid = port.get("portid")
        protocol = port.get("protocol")
        service = port.find("service")
        svc_name = service.get("name") if service is not None else "desconocido"
        svc_product = service.get("product") if service is not None else None
        svc_version = service.get("version") if service is not None else None

        detalle = f"{portid}/{protocol} open {svc_name}"
        if svc_product:
            detalle += f" ({svc_product}{' ' + svc_version if svc_version else ''})"

        findings.append({"name": "PORT", "detail": detalle, "severity": "info"})

    return findings
