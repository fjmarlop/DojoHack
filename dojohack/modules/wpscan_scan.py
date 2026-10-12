"""
Módulo wpscan — enumeración de WordPress (núcleo, plugins, temas,
usuarios, backups/exports expuestos...). Igual que el resto: binario
externo, cero lógica propia de detección que reescribir en clean-room.

Se lanza siempre que hay un target web, igual que ffuf/katana/dalfox/
trufflehog — no hace falta confirmar antes que es WordPress: si no lo
es, wpscan no detecta un core válido y el módulo devuelve 0 hallazgos
en unos segundos (ver run(): json.JSONDecodeError / sin "version" se
tratan como "no es WordPress", no como fallo).

Enumeración completa (-e ap,at,tt,cb,dbe,bf,u,m: todos los plugins,
todos los temas, timthumbs, backups de config, exports de DB, carpetas
de backup, usuarios 1-10, media 1-100) en vez del subconjunto "solo
vulnerables" (vp,vt,...) que trae -e por defecto sin argumentos —
coherente con "arsenal completo, sin recortar" (ver CLAUDE.md): un
plugin sin vulnerabilidad conocida HOY sigue siendo superficie de
ataque real y dato de reconocimiento (ver el campo "outdated").

LIMITACIÓN CONOCIDA: sin --api-token (no hay uno de wpscan.com
configurado en este equipo), wpscan no puede cruzar plugins/temas/
core contra su base de datos de CVEs — "vulnerabilities" viene vacío
en todos los hallazgos, confirmado contra un lab real. El campo
version.status ("insecure"/"latest") sí llega sin token (es una
comprobación aparte, más simple). Si algún día hay un token (gratis,
25 peticiones/día en wpscan.com/register), añadirlo aquí con
--api-token activaría esos datos sin más cambios en el parseo.

Usa -f json (un único objeto con todo el scan) en vez de la salida de
consola — mismo motivo que el resto: formato estable entre versiones.
"""

import json

from .. import subprocess_utils

ENUMERATE = "ap,at,tt,cb,dbe,bf,u,m"


def run(web_target) -> list[dict]:
    """Devuelve una lista de hallazgos con el mismo convenio que el
    resto de módulos: {"name", "detail", "severity"}. El timeout lo
    controla dojohack.timeouts.run_module, no esta función."""
    proc = subprocess_utils.run(
        [
            "wpscan", "--url", f"{web_target.base_url}/",
            "-e", ENUMERATE, "-f", "json", "--no-banner",
        ],
        text=True,
    )
    # wpscan devuelve códigos de salida distintos según lo que
    # encuentre (p.ej. vulnerabilidades) — no es señal de fallo real
    # por sí solo; solo se trata como error si tampoco hay stdout que
    # parsear.
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"wpscan devolvió código {proc.returncode}: {proc.stderr[:300]}")

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    version = data.get("version") or {}
    if not version.get("number"):
        return []  # no se detectó un core de WordPress válido: no es WP (o no se pudo confirmar)

    findings = [{
        "name": "WPSCAN",
        "detail": f"WordPress {version['number']} (estado: {version.get('status', 'desconocido')})",
        "severity": "medium" if version.get("status") == "insecure" else "info",
    }]

    main_theme = data.get("main_theme")
    if main_theme:
        theme_version = (main_theme.get("version") or {}).get("number", "")
        findings.append({
            "name": "WPSCAN",
            "detail": f"tema activo: {main_theme.get('slug', '?')} {theme_version}".strip(),
            "severity": "info",
        })

    for slug, plugin in (data.get("plugins") or {}).items():
        version_num = (plugin.get("version") or {}).get("number")
        detalle = f"plugin '{slug}'"
        if version_num:
            detalle += f" {version_num}"
        if plugin.get("outdated"):
            detalle += f" (desactualizado, última: {plugin.get('latest_version', '?')})"
        if plugin.get("directory_listing"):
            detalle += " — listado de directorio activado en su carpeta"
        findings.append({"name": "WPSCAN", "detail": detalle, "severity": "info"})

    for username, user in (data.get("users") or {}).items():
        findings.append({
            "name": "WPSCAN",
            "detail": f"usuario encontrado: {username}",
            "severity": "info",
        })

    for item in data.get("interesting_findings") or []:
        texto = item.get("to_s") or item.get("url", "")
        if texto:
            findings.append({"name": "WPSCAN", "detail": texto, "severity": "info"})

    return findings
