"""
Sonda SSTI (Server-Side Template Injection) — WSTG-INPV-18.

Primera sonda propia del proyecto: lógica de detección escrita desde
cero a partir de la metodología pública OWASP WSTG, sin mirar
wstg-scan (ver CLAUDE.md — clean-room). nmap/nuclei/ffuf/katana/
dalfox/trufflehog son binarios de terceros invocados por subprocess,
sin lógica de detección propia que reescribir; esto sí la tiene, y es
la primera.

Metodología: se inyecta una expresión aritmética con la sintaxis de
varios motores de plantillas habituales (Jinja2/Twig/Pebble,
FreeMarker/EL/Thymeleaf, ERB, Smarty) en cada punto de inyección (un
parámetro GET o un campo de formulario POST). Si el motor evalúa la
expresión en vez de tratarla como texto literal, el resultado
calculado (ej. "49") aparece en la respuesta en vez del payload
crudo.

Cada payload mete DOS operaciones distintas en la misma petición
("{{7*7}}_{{8*8}}" → se espera "49_64" en vez de "{{7*7}}_{{8*8}}")
en vez de solo una. Que aparezcan ambos resultados, cada uno en su
sitio, es mucho más improbable por casualidad (una página que por lo
que sea ya devuelve "49" en algún otro punto, una respuesta
cacheada...) que si solo se comprobara un número suelto.

Igual que el resto de hallazgos del proyecto: esto solo señala la
técnica a explorar, no identifica el motor exacto ni intenta
explotarlo más allá de confirmar que algo se evalúa — identificar el
motor concreto y escalar es justo el trabajo que le toca a Paco, no
algo que deba regalarle la herramienta.
"""

import httpx

TIMEOUT = 10

# (familia de motores, payload con dos operaciones, resultado esperado)
PAYLOAD_FAMILIES = [
    ("Jinja2/Twig/Pebble", "{{7*7}}_{{8*8}}", "49_64"),
    ("FreeMarker/EL/Thymeleaf", "${7*7}_${8*8}", "49_64"),
    ("ERB (Ruby)", "<%= 7*7 %>_<%= 8*8 %>", "49_64"),
    ("Smarty", "{7*7}_{8*8}", "49_64"),
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
    for familia, payload, esperado in PAYLOAD_FAMILIES:
        try:
            body = _send(client, point, payload)
        except httpx.HTTPError:
            continue
        if esperado in body and payload not in body:
            return {
                "name": "SSTI",
                "detail": (
                    f"{point['method']} {point['url']} — el parámetro '{point['param']}' "
                    f"huele a Server-Side Template Injection: al meterle una expresión con "
                    f"sintaxis de plantillas ({familia}), la respuesta cambió de forma que "
                    f"sugiere que se está evaluando en vez de tratarse como texto plano. "
                    f"Por ahí podría haber algo — vale la pena tirar del hilo con distintos "
                    f"motores de plantillas y ver hasta dónde llega."
                ),
                "severity": "high",
            }
    return None


def run(injection_points: list[dict]) -> list[dict]:
    """Devuelve una lista de hallazgos (uno por punto de inyección
    donde se detecta SSTI), con el mismo convenio que el resto de
    módulos: {"name", "detail", "severity"}. El timeout lo controla
    dojohack.timeouts.run_module, no esta función."""
    findings = []
    with httpx.Client(follow_redirects=True) as client:
        for point in injection_points:
            result = _test_point(client, point)
            if result:
                findings.append(result)
    return findings
