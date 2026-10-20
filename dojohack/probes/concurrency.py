"""
Ejecuta _test_point() de las sondas propias en paralelo sobre varios
puntos de inyección a la vez, en vez de uno a uno. Con listas de
cientos de puntos (frecuente en una app WordPress real detrás de ARJUN
— 235 puntos visto en el lab academy) la versión secuencial se come el
timeout del módulo sin necesidad: no hay WAF ni SOC en un lab de
práctica que penalice ir en paralelo (ver conversación con Paco,
2026-10-20).

MAX_WORKERS se mantiene moderado (no "todo lo que dé la CPU"): sqli.py
y command_injection.py tienen detección ciega por tiempo (miden cuánto
tarda la respuesta tras inyectar un `sleep`) — demasiada concurrencia
satura el pool de procesos/hilos del servidor real (ej. Apache
prefork con tope de workers) y mete ruido en ESA medición para todos
los puntos en vuelo a la vez, no solo para el que de verdad sea
vulnerable. 16 es rápido de sobra para los cientos de puntos vistos
hasta ahora sin acercarse a ese límite en un lab normal.
"""

from concurrent.futures import ThreadPoolExecutor

MAX_WORKERS = 16


def run_points(test_point, client, points: list[dict]) -> list[dict]:
    """Aplica test_point(client, point) a cada punto en un pool de
    hilos, compartiendo el mismo cliente httpx (seguro entre hilos
    para uso síncrono) y devuelve los hallazgos no nulos."""
    if not points:
        return []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        resultados = pool.map(lambda point: test_point(client, point), points)
        return [r for r in resultados if r]
