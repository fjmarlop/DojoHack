"""
Módulo trufflehog — búsqueda de secretos en un .git expuesto.

trufflehog no tiene un modo "escanea esta web": sus fuentes son repos
git, sistemas de ficheros, buckets, etc. El caso de uso real para un
pipeline de recon web es la vulnerabilidad clásica de "directorio
.git expuesto" (descuido habitual al desplegar: el servidor sirve
/.git/ tal cual) — se puede clonar por HTTP "dumb" y trufflehog
encuentra secretos en el historial, incluidos los que ya no están en
el HEAD actual pero siguen en commits viejos.

Por eso el módulo primero comprueba barato (una sola petición a
/.git/HEAD, con stdlib urllib — no hace falta una librería HTTP para
esto) si el target expone un repo git servido por error, y solo si lo
expone intenta `trufflehog git` contra esa URL. Si no lo expone, no
hay nada que escanear: 0 hallazgos, no es un fallo del módulo.

Se valida que /.git/HEAD responde con el formato real de un ref git
("ref: refs/...") y no solo que la ruta devuelve 200 — un servidor
con fallback genérico (p.ej. una SPA) podría devolver 200 en
cualquier ruta sin que haya un repo de verdad.

Recibe un dojohack.web_targets.WebTarget (no un target suelto) y mira
web_target.base_url + "/.git/..." — importante cuando la app está en
un subdirectorio (ver ffuf_scan.py): el .git expuesto, si lo hay,
sería el de esa app, no el de la raíz del servidor.
"""

import json
import urllib.error
import urllib.request

from .. import subprocess_utils


def _exposes_git(web_target) -> bool:
    url = f"{web_target.base_url}/.git/HEAD"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            if resp.status != 200:
                return False
            return resp.read(100).startswith(b"ref:")
    except (urllib.error.URLError, OSError):
        return False


def run(web_target) -> list[dict]:
    """Devuelve una lista de hallazgos, uno por secreto encontrado,
    con el mismo convenio que el resto de módulos: {"name", "detail",
    "severity"}. El timeout lo controla dojohack.timeouts.run_module,
    no esta función."""
    if not _exposes_git(web_target):
        return []

    git_url = f"{web_target.base_url}/.git/"
    proc = subprocess_utils.run(
        ["trufflehog", "git", git_url, "--json", "--no-update"],
        text=True,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"trufflehog devolvió código {proc.returncode}: {proc.stderr[:300]}")

    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "DetectorName" not in item:
            continue  # línea de log info-0, no un hallazgo

        detector = item.get("DetectorName", "desconocido")
        verified = item.get("Verified", False)
        git_meta = item.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
        commit = (git_meta.get("commit") or "")[:8]
        file_ = git_meta.get("file", "")
        raw = item.get("Raw", "")

        detalle = f"{detector}: {raw}"
        if file_:
            detalle += f" en {file_}"
        if commit:
            detalle += f" (commit {commit})"

        severity = "high" if verified else "medium"
        findings.append({"name": "TRUFFLEHOG", "detail": detalle, "severity": severity})

    return findings
