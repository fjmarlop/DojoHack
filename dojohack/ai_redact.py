"""
Pasada de redacción opcional con Claude sobre el recon_writeup.md
(flag --polish). Nunca decide qué es un hallazgo ni su confianza —
eso sigue siendo 100% determinista en preprocessor.py/classifier.py
(ver CLAUDE.md: "las pistas finales... la confianza SÍ se calcula
internamente... mediante reglas", sin IA en esa capa) — esto solo
reescribe PROSA sobre pistas+contexto ya decididos, para conectar
hallazgos relacionados en vez de dejarlos como bullets sueltos por
categoría de herramienta, y variar el tono en vez de repetir
plantillas fijas (ver conversación con Paco, 2026-10-15/16, sobre
redacción del informe).

Opt-in (--polish, apagado por defecto): el pipeline sigue siendo
100% determinista/offline salvo que se pida explícitamente. Si algo
falla (sin ANTHROPIC_API_KEY, sin el paquete `anthropic` instalado,
sin red, error de la API, respuesta con formato inesperado...) esto
devuelve None en vez de levantar — cli.py cae entonces a
report.render_writeup() tal cual, nunca rompe el pipeline por esto.

Cubre ÚNICAMENTE lo mismo que report.render_writeup(): Reconocimiento
y Enumeración web. Nunca Explotación/Foothold/Escalada de
privilegios/Flags — eso es 100% trabajo de Paco a mano en su flujo de
writeups aparte (~/ctf/CLAUDE.md, repo distinto de este).
"""

import os

from . import report

MODEL = "claude-haiku-5-5"  # tarea de redacción, no de razonamiento: el modelo mas barato/rapido sobra

SYSTEM_PROMPT = """Eres un redactor técnico. Vas a recibir un listado ya decidido de hallazgos de reconocimiento (puertos, rutas, plugins, usuarios...) de una herramienta de recon para practicar CTF. Tu única tarea es reescribir ese contenido en prosa más legible y conectada, bajo los headers "## Reconocimiento" y "## Enumeración web" exactamente (nada más, ningún otro header, ninguna otra sección).

Reglas estrictas, sin excepción:
- No inventes ningún hallazgo que no esté ya en el listado dado.
- No cambies ni insinúes severidad o confianza distinta a la que ya tiene el texto original.
- Nunca digas "confirmado" de nada ni distingas en el texto qué es heurístico vs verificado — todo igual de dubitativo, tal y como ya viene redactado.
- No den pasos de explotación, payloads nuevos, ni comandos a ejecutar que no estén ya literalmente en el listado dado.
- Puedes: reordenar, agrupar hallazgos relacionados en un mismo párrafo o viñeta, variar el tono para que no suene a plantilla repetida, añadir una frase breve de resumen al principio de cada sección.
- Responde solo con el markdown final (empezando por "## Reconocimiento"), sin explicaciones tuyas ni texto fuera de esas dos secciones."""


def polish(target: str, pistas: list[dict], contexto: list[str]) -> str | None:
    """Pide a Claude que reescriba report.render_writeup() en mejor
    prosa, sin cambiar qué cuenta como hallazgo. Devuelve el markdown
    reescrito, o None si no se puede por cualquier motivo (nunca
    levanta) — para que cli.py siempre tenga la versión determinista
    como alternativa segura."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None

    try:
        import anthropic
    except ImportError:
        return None

    base = report.render_writeup(target, pistas, contexto)

    try:
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Target: {target}\n\n{base}"}],
        )
        texto = "".join(block.text for block in resp.content if block.type == "text").strip()
    except Exception:
        return None

    if not texto.startswith("## Reconocimiento"):
        return None  # formato inesperado: mejor caer a la version determinista que arriesgar un writeup roto

    return texto
