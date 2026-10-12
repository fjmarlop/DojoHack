"""
Módulo nmap — el primero del pipeline, deliberadamente el más simple:
es un binario externo, cero lógica propia de detección que reescribir
en clean-room. Sirve para validar el cableado completo (timeout,
feedback en vivo, guardado) antes de sumar el resto de módulos.

Usa -oX - (XML a stdout) en vez de parsear la salida de texto plano —
mucho más fiable entre versiones de nmap que fiarse del formato de
impresión, que cambia entre versiones.

Usa -p- (los 65535 puertos, no solo el top-1000 por defecto de nmap):
coherente con "arsenal completo, sin recortar por tratarse de CTF"
(ver CLAUDE.md) — recortar aquí significaría no ver puertos altos
poco habituales que en un CTF suelen ser justo donde está el reto.

Usa -sC (scripts por defecto) además de -sV: no cuesta una herramienta
nueva y da recon gratis que antes se perdía — ftp-anon (login anónimo
permitido), ssl-cert (el nombre del certificado puede revelar el
hostname real cuando hay vhosting, justo lo que había que fuzzear a
mano contra 192.168.72.134), smb-os-discovery, etc. Cada script que
produce output se guarda como su propio hallazgo (categoría
NMAP_SCRIPT), no mezclado con el de PORT — mismo motivo que separar
RUTA_SOSPECHOSA de FFUF: son dos tipos de evidencia distintos aunque
vengan del mismo módulo.
"""

import xml.etree.ElementTree as ET

from .. import subprocess_utils


def run(target: str) -> list[dict]:
    """Devuelve una lista de hallazgos — uno por puerto abierto (PORT) y
    uno más por cada script de -sC que haya producido salida
    (NMAP_SCRIPT) — con el mismo convenio que PocketHacker
    (preprocessor.py): {"name", "detail", "severity"}. El timeout lo
    controla dojohack.timeouts.run_module, no esta función."""
    proc = subprocess_utils.run(
        ["nmap", "-Pn", "-sV", "-sC", "-p-", "-T4", "-oX", "-", target],
        text=True,
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

        for script in port.findall("script"):
            script_id = script.get("id", "desconocido")
            output = " ".join((script.get("output") or "").split())
            if not output:
                continue
            findings.append({
                "name": "NMAP_SCRIPT",
                "detail": f"{portid}/{protocol} {script_id}: {output[:300]}",
                "severity": "info",
            })

    return findings
