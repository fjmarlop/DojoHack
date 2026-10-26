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

-t 50 (su defecto es 5 — pensado para no llamar la atención en un
engagement real; aquí no hay WAF ni SOC que evitar, así que no tiene
sentido ir tan despacio, ver conversación con Paco, 2026-10-20).

Token de wpscan.com (gratis, 25 peticiones/día en wpscan.com/register)
opcional vía la variable de entorno WPSCAN_API_TOKEN — nunca como
argumento de dojohack ni guardado en ningún fichero de este proyecto,
mismo criterio que ANTHROPIC_API_KEY en ai_redact.py: se lee de
os.environ en el momento de lanzar wpscan, nunca se escribe en
ningún log/finding/fichero de salida. Se pone en la misma línea del
comando (no export, no ~/.zshrc, para que no quede puesta de forma
permanente — ver conversación con Paco, 2026-10-26):

    WPSCAN_API_TOKEN=xxxx dojohack <target> ...

Sin el token, "vulnerabilities" viene vacío en todos los hallazgos
(confirmado contra un lab real) y _vuln_summary() nunca añade nada —
el campo version.status ("insecure"/"latest") sí llega igual, es una
comprobación aparte más simple que no necesita token.

Usa -f json (un único objeto con todo el scan) en vez de la salida de
consola — mismo motivo que el resto: formato estable entre versiones.
"""

import json
import os

from .. import subprocess_utils

ENUMERATE = "ap,at,tt,cb,dbe,bf,u,m"


def _vuln_summary(vulnerabilities: list[dict] | None) -> str:
    """Resumen corto de las vulnerabilidades conocidas que wpscan.com
    cruza contra una versión (solo llega con WPSCAN_API_TOKEN) —
    título + CVE si lo trae, hasta 3, con un "+N más" si hay más."""
    if not vulnerabilities:
        return ""
    etiquetas = []
    for v in vulnerabilities[:3]:
        cves = (v.get("references") or {}).get("cve") or []
        etiquetas.append(f"{v.get('title', '?')}" + (f" (CVE-{cves[0]})" if cves else ""))
    resto = len(vulnerabilities) - len(etiquetas)
    texto = "; ".join(etiquetas)
    if resto > 0:
        texto += f"; +{resto} más"
    return f" — {len(vulnerabilities)} vulnerabilidad(es) conocida(s): {texto}"


def run(web_target, timeout: int | None = None) -> list[dict]:
    """Devuelve una lista de hallazgos con el mismo convenio que el
    resto de módulos: {"name", "detail", "severity"}. `timeout` se
    propaga a subprocess_utils.run() — cli.py lo lanza en paralelo con
    otros módulos independientes vía timeouts.run_threadsafe (ver ese
    módulo para el porqué)."""
    args = [
        "wpscan", "--url", f"{web_target.base_url}/",
        "-e", ENUMERATE, "-f", "json", "--no-banner", "-t", "50",
    ]
    token = os.environ.get("WPSCAN_API_TOKEN")
    if token:
        args += ["--api-token", token]

    proc = subprocess_utils.run(args, text=True, timeout=timeout)
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

    core_vulns = version.get("vulnerabilities")
    findings = [{
        "name": "WPSCAN",
        "detail": (
            f"WordPress {version['number']} (estado: {version.get('status', 'desconocido')})"
            f"{_vuln_summary(core_vulns)}"
        ),
        "severity": "high" if core_vulns else ("medium" if version.get("status") == "insecure" else "info"),
    }]

    main_theme = data.get("main_theme")
    if main_theme:
        theme_version = (main_theme.get("version") or {}).get("number", "")
        theme_vulns = main_theme.get("vulnerabilities")
        findings.append({
            "name": "WPSCAN",
            "detail": f"tema activo: {main_theme.get('slug', '?')} {theme_version}".strip() + _vuln_summary(theme_vulns),
            "severity": "high" if theme_vulns else "info",
        })

    for slug, plugin in (data.get("plugins") or {}).items():
        version_num = (plugin.get("version") or {}).get("number")
        plugin_vulns = plugin.get("vulnerabilities")
        detalle = f"plugin '{slug}'"
        if version_num:
            detalle += f" {version_num}"
        if plugin.get("outdated"):
            detalle += f" (desactualizado, última: {plugin.get('latest_version', '?')})"
        if plugin.get("directory_listing"):
            detalle += " — listado de directorio activado en su carpeta"
        detalle += _vuln_summary(plugin_vulns)
        findings.append({
            "name": "WPSCAN", "detail": detalle,
            "severity": "high" if plugin_vulns else "info",
        })

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
