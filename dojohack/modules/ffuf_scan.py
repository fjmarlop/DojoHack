"""
Módulo ffuf — fuzzing de directorios/rutas. Igual que nmap y nuclei:
binario externo, cero lógica propia de detección que reescribir en
clean-room.

Wordlist por defecto: raft-medium-directories.txt de SecLists (viene
con el paquete `seclists` de Kali). Es una lista moderna, curada
específicamente para directorios — a diferencia de las DirBuster-2007
(probadas primero): esas incluyen una cabecera de licencia como líneas
de comentario con '#', y el parser de URLs de ffuf las trunca ahí,
acabando por pedir '/' en vez del path real — falsos positivos
comprobados contra un target real del lab (casapaco.thl).

No se usa -ac (auto-calibración de ffuf): en esa misma prueba, -ac
descartó /server-status (403) como "ruido" de calibración, cuando en
realidad es un hallazgo real (mod_status expuesto, confirmado con
curl). Mejor pecar de mostrar de más que ocultar un hallazgo válido —
coherente con la filosofía del proyecto de no quitarle a Paco el
esfuerzo de decidir qué es real. Solo se filtra -fc 404 (caso
inequívoco: la ruta no existe).

LIMITACIONES CONOCIDAS (v1, a revisar si hace falta más adelante):
- Solo fuzzing de directorios/rutas, sin extensiones de fichero
  (.php, .bak...) — eso es otra técnica, se añadirá aparte si hace
  falta, no entra en "fuzzing de directorios".
- Asume esquema http. Si el target solo sirve https, hay que pasar
  wordlist/target ya pensando en ello (no hay auto-detección todavía).
"""

import json
import subprocess
import tempfile
from pathlib import Path

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"


def run(target: str, wordlist: str = DEFAULT_WORDLIST) -> list[dict]:
    """Devuelve una lista de hallazgos, uno por ruta encontrada, con
    el mismo convenio que el resto de módulos: {"name", "detail",
    "severity"}. El timeout lo controla dojohack.timeouts.run_module,
    no esta función."""
    if not Path(wordlist).is_file():
        raise RuntimeError(f"wordlist no encontrada: {wordlist}")

    url = f"http://{target}/FUZZ"

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    try:
        proc = subprocess.run(
            [
                "ffuf", "-u", url, "-w", wordlist,
                "-mc", "all", "-fc", "404",
                "-o", out_path, "-of", "json", "-s",
            ],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"ffuf devolvió código {proc.returncode}: {proc.stderr[:300]}")

        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)
    finally:
        Path(out_path).unlink(missing_ok=True)

    findings = []
    for r in data.get("results", []):
        status = r.get("status")
        length = r.get("length")
        path = r.get("url", "")
        detalle = f"{status} {path} ({length} bytes)"
        findings.append({"name": "FFUF", "detail": detalle, "severity": "info"})

    return findings
