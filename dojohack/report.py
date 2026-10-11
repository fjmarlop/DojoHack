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
"""

import datetime


def _agrupar_por_categoria(pistas: list[dict]) -> dict[str, list[dict]]:
    agrupado: dict[str, list[dict]] = {}
    for p in pistas:
        agrupado.setdefault(p["categoria"], []).append(p)
    return agrupado


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
