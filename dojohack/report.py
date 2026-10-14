"""
Informe final — terminal + fichero .md (último paso de la hoja de
ruta). Nunca HTML con plantilla de informe de cliente — eso es
PocketHacker, no DojoHack (ver CLAUDE.md). El .md está pensado para
caer directo en el vault de Obsidian de Paco (su flujo habitual de
writeups), con una cabecera YAML sencilla al estilo Obsidian.

No se usa color/formato por severidad en ningún sitio: las pistas ya
vienen deliberadamente sin distinguir "confirmado" de "heurístico" en
el texto (ver classifier.py) — maquetar unas con más fuerza visual
que otras filtraría esa misma información por otra vía y le quitaría
a Paco parte del criterio que se supone que tiene que poner él.
render_writeup() es aparte: genera un fragmento (no un documento con
cabecera propia) pensado para pegar literalmente en el flujo de
writeups de Paco (~/ctf/CLAUDE.md, repo separado de este) como
contenido de un "toma nota" — nunca para que DojoHack escriba
directamente en las notas de esa sesión, que son la narración de Paco,
no un volcado de herramienta (ver conversación con Paco, 2026-10-15).
Por eso solo cubre Reconocimiento/Enumeración web — las secciones de
esa plantilla que vienen de herramientas automatizadas — y nunca
Explotación/Foothold/Escalada de privilegios/Flags, que son 100%
trabajo confirmado por Paco a mano.
"""

import datetime
import re


def _agrupar_por_categoria(pistas: list[dict]) -> dict[str, list[dict]]:
    agrupado: dict[str, list[dict]] = {}
    for p in pistas:
        agrupado.setdefault(p["categoria"], []).append(p)
    return agrupado


# Categorías de reconocimiento a nivel de host/servicio — van bajo
# "## Reconocimiento" en render_writeup(). Todo lo demás (ffuf/katana/
# wpscan/arjun/nuclei/dalfox/trufflehog/las sondas propias/rutas
# sospechosas/vhost) va bajo "## Enumeración web": viene de sondear la
# app web, no el host en general. Aproximado para NUCLEI (mezcla
# plantillas web y no-web bajo una sola categoría) — se deja en
# Enumeración web porque la mayoría de lo visto hasta ahora en labs
# reales ha sido justo eso.
_CATEGORIAS_RECON = {"PORT", "NMAP_SCRIPT", "ENUM4LINUX", "TESTSSL"}

_CONTEXTO_RE = re.compile(r"^\[(\w+)\]\s*(.*)$")


def render_writeup(target: str, pistas: list[dict], contexto: list[str]) -> str:
    """Fragmento Markdown con el contenido de pistas+contexto ya
    repartido en Reconocimiento/Enumeración web, bajo los mismos
    headers que usa la plantilla fija de ~/ctf/CLAUDE.md — para pegar
    tal cual como "toma nota", no para sustituir ese informe."""
    recon: list[str] = []
    web: list[str] = []

    for c in contexto:
        m = _CONTEXTO_RE.match(c)
        if not m:
            web.append(c)
            continue
        categoria, texto = m.groups()
        (recon if categoria in _CATEGORIAS_RECON else web).append(texto)

    for p in pistas:
        (recon if p["categoria"] in _CATEGORIAS_RECON else web).append(p["texto"])

    lineas = [
        f"<!-- Generado por DojoHack contra {target} — contenido literal, "
        f"para pegar como \"toma nota\" en la sesión de writeup -->",
        "",
        "## Reconocimiento",
        "",
    ]
    lineas += [f"- {t}" for t in recon] if recon else ["(nada que mostrar)"]
    lineas += ["", "## Enumeración web", ""]
    lineas += [f"- {t}" for t in web] if web else ["(nada que mostrar)"]
    lineas.append("")

    return "\n".join(lineas)


def render_markdown(target: str, pistas: list[dict], contexto: list[str]) -> str:
    """Versión completa para el fichero .md — incluye todo el
    contexto de reconocimiento, pensada para consultarse más tarde,
    no solo en el momento."""
    fecha = datetime.date.today().isoformat()
    lineas = [
        "---",
        f"target: {target}",
        f"fecha: {fecha}",
        "tags: [ctf, dojohack]",
        "---",
        "",
        f"# DojoHack — {target}",
        "",
        "_Pistas de reconocimiento, no soluciones — el resto es cosa tuya._",
        "",
        "## Pistas",
        "",
    ]

    if pistas:
        agrupado = _agrupar_por_categoria(pistas)
        for categoria, items in agrupado.items():
            lineas.append(f"### {categoria}")
            lineas.append("")
            for p in items:
                lineas.append(f"- {p['texto']}")
            lineas.append("")
    else:
        lineas.append(
            "No ha salido nada que merezca pista en esta pasada. Puede que "
            "haga falta mirar más a mano, o que el reto esté en algo que el "
            "pipeline no cubre todavía."
        )
        lineas.append("")

    lineas.append("## Contexto (reconocimiento, sin pista asociada)")
    lineas.append("")
    if contexto:
        for c in contexto:
            lineas.append(f"- {c}")
    else:
        lineas.append("(nada que mostrar)")
    lineas.append("")

    return "\n".join(lineas)


def render_terminal(target: str, pistas: list[dict], contexto: list[str]) -> str:
    """Versión para stdout: las pistas completas (es lo que Paco
    quiere ver nada más terminar el pipeline), pero el contexto solo
    como recuento — el detalle completo se queda en el .md."""
    lineas = ["", "=" * 60, f"  DojoHack — {target}", "=" * 60]

    if pistas:
        lineas.append("")
        lineas.append(f"Pistas ({len(pistas)}):")
        agrupado = _agrupar_por_categoria(pistas)
        for categoria, items in agrupado.items():
            lineas.append(f"  [{categoria}]")
            for p in items:
                lineas.append(f"    - {p['texto']}")
    else:
        lineas.append("")
        lineas.append(
            "Pistas: ninguna esta vez. Puede que haga falta mirar más a mano, "
            "o que el reto esté en algo que el pipeline no cubre todavía."
        )

    lineas.append("")
    lineas.append(f"Contexto: {len(contexto)} líneas de reconocimiento (detalle completo en el .md)")
    lineas.append("=" * 60)

    return "\n".join(lineas)
