"""
Sonda Command Injection (OS Command Injection) — OWASP WSTG-INPV-12.

Quinta sonda propia, escrita desde cero a partir de la metodología
pública OWASP WSTG (sin mirar wstg-scan — ver CLAUDE.md, clean-room).
Directamente relevante para el tipo de retos que se vienen trabajando
(una de las máquinas de Paco se resuelve en parte por RCE).

Dos técnicas, misma estructura que sqli.py/ssti.py/path_traversal.py:

1. Basada en salida: inyecta el parámetro encadenado con un comando
   inocuo (id en Linux, whoami en Windows) usando varios separadores
   de shell (; | $() `` ` `` &) y busca en la respuesta algo que
   parezca la salida real de ese comando — solo se reconoce el patrón
   de Linux (uid=.../gid=...), nunca "algo\algo" genérico para
   Windows: contra un lab real, ese patrón suelto coincidió con
   🏳 (el escape JSON de un emoji que WordPress incrusta en
   su script de detección de emojis, presente en CUALQUIER página),
   generando 24 falsos positivos idénticos. Además de recortar el
   patrón, se compara contra una respuesta de referencia sin payload
   — si la "salida" ya estaba ahí antes de inyectar nada, no cuenta
   (mismo principio que el resto de sondas: una coincidencia no es
   evidencia si ya estaba antes del payload).

2. Ciega por tiempo: igual que en sqli.py, inyecta un retardo (sleep
   en Linux, ping como aproximación en Windows — Windows no tiene un
   "sleep" de shell nativo universal) y compara contra una petición
   de referencia. Es la única señal cuando el comando se ejecuta pero
   nada de su salida llega a reflejarse en la respuesta.

Se para en "parece que hay inyección" — no intenta encadenar hacia una
reverse shell ni confirmar RCE completo, que ya sería la solución, no
la pista (ver CLAUDE.md).
"""

import re
import time

import httpx

from . import concurrency

TIMEOUT = 12
SLEEP_SECONDS = 5
TIME_THRESHOLD = 4  # margen por debajo de SLEEP_SECONDS, para tolerar jitter de red

# (nombre, payload)
OUTPUT_PAYLOADS = [
    ("Linux, encadenado con ;", "; id"),
    ("Linux, con pipe", "| id"),
    ("Linux, subshell $()", "$(id)"),
    ("Linux, backticks", "`id`"),
    ("Windows, encadenado con &", "& whoami"),
]
# uid=1000(usuario) gid=... de Linux. Deliberadamente NO se reconoce
# "algo\algo" como firma de "DOMINIO\usuario" de Windows — ver nota
# arriba sobre por qué eso fue un falso positivo real contra un lab.
OUTPUT_SIGNATURE = re.compile(r"uid=\d+\([^)]*\)", re.I)

TIME_PAYLOADS = [
    ("Linux, encadenado con ;", f"; sleep {SLEEP_SECONDS}"),
    ("Linux, con pipe", f"| sleep {SLEEP_SECONDS}"),
    ("Linux, subshell $()", f"$(sleep {SLEEP_SECONDS})"),
    ("Windows, ping como retardo", f"& ping -n {SLEEP_SECONDS + 1} 127.0.0.1"),
]


def _send(client: httpx.Client, point: dict, value: str) -> tuple[str, float]:
    params = dict(point.get("params", {}))
    params[point["param"]] = value
    t0 = time.monotonic()
    if point["method"] == "GET":
        resp = client.get(point["url"], params=params, timeout=TIMEOUT)
    else:
        resp = client.post(point["url"], data=params, timeout=TIMEOUT)
    return resp.text, time.monotonic() - t0


def _finding(point: dict, evidencia: str) -> dict:
    return {
        "name": "COMMAND_INJECTION",
        "detail": (
            f"{point['method']} {point['url']} — el parámetro '{point['param']}' "
            f"huele a inyección de comandos del sistema: {evidencia}. Por ahí "
            f"podría llegarse a ejecución de código en el servidor — vale la "
            f"pena tirar del hilo con cuidado."
        ),
        "severity": "high",
    }


def _test_point(client: httpx.Client, point: dict) -> dict | None:
    try:
        baseline_body, baseline = _send(client, point, "1")
    except httpx.HTTPError:
        return None

    for nombre, payload in OUTPUT_PAYLOADS:
        try:
            body, _ = _send(client, point, payload)
        except httpx.HTTPError:
            continue
        m = OUTPUT_SIGNATURE.search(body)
        if m and payload not in body and m.group(0) not in baseline_body:
            return _finding(
                point,
                f"al meter un payload encadenando comandos ({nombre}) apareció "
                f"en la respuesta algo que parece salida real de un comando "
                f"('{m.group(0)}'), que no estaba ya en una respuesta de "
                f"referencia sin ese payload",
            )

    for nombre, payload in TIME_PAYLOADS:
        try:
            _, elapsed = _send(client, point, payload)
        except httpx.HTTPError:
            continue
        if elapsed - baseline >= TIME_THRESHOLD:
            return _finding(
                point,
                f"al meter un retardo encadenando comandos ({nombre}) la "
                f"respuesta tardó {elapsed:.1f}s frente a los {baseline:.1f}s "
                f"de referencia sin payload — huele a inyección ciega por tiempo",
            )

    return None


def run(injection_points: list[dict]) -> list[dict]:
    """Devuelve una lista de hallazgos (uno por punto de inyección
    donde se detecta inyección de comandos), con el mismo convenio que
    el resto de módulos: {"name", "detail", "severity"}. El timeout lo
    controla dojohack.timeouts.run_module, no esta función. Los puntos
    se prueban en paralelo con un tope moderado de hilos (ver
    concurrency.py) — suficiente para no comerse el timeout del
    módulo con cientos de puntos (lo que pasaba antes: 235 puntos ×
    hasta 10 peticiones secuenciales cada uno superaban los 300s sin
    que el target fuera lento en sí), sin tantos a la vez como para
    meter ruido en la detección ciega por tiempo (TIME_PAYLOADS)."""
    with httpx.Client(follow_redirects=True) as client:
        return concurrency.run_points(_test_point, client, injection_points)
