"""
Módulo ffuf — fuzzing de directorios/rutas. Igual que nmap y nuclei:
binario externo, cero lógica propia de detección que reescribir en
clean-room.

Wordlist por defecto: raft-medium-directories.txt de SecLists (viene
con el paquete `seclists` de Kali). Es una lista moderna, curada
específicamente para directorios — a diferencia de las DirBuster-2007
(probadas primero): esas incluyen una cabecera de licencia como líneas
de comentario con '#', y el parser de URLs de ffuf las trunca ahí,
acabando por pedir '/' en vez del path real — falsos positivos
comprobados contra un target real del lab (casapaco.thl).

No se usa -ac (auto-calibración de ffuf): en esa misma prueba, -ac
descartó /server-status (403) como "ruido" de calibración, cuando en
realidad es un hallazgo real (mod_status expuesto, confirmado con
curl). Mejor pecar de mostrar de más que ocultar un hallazgo válido —
coherente con la filosofía del proyecto de no quitarle a Paco el
esfuerzo de decidir qué es real. Solo se filtra -fc 404 (caso
inequívoco: la ruta no existe).

LIMITACIONES CONOCIDAS (v1, a revisar si hace falta más adelante):
- Solo fuzzing de directorios/rutas, sin extensiones de fichero
  (.php, .bak...) — eso es otra técnica, se añadirá aparte si hace
  falta, no entra en "fuzzing de directorios".

Recibe un dojohack.web_targets.WebTarget (esquema/puerto/ruta base ya
resueltos a partir de lo que encontró nmap — o del --base-path que se
le haya pasado a mano), no un target suelto — así no asume siempre
http en el puerto 80, ni la raíz como punto de partida (ver
web_targets.py: la app puede estar en otro puerto, por https, o en un
subdirectorio, como pasó con /wordpress en 192.168.72.134).

FILTRO DE CALIBRACIÓN ANTI CATCH-ALL (añadido tras una ejecución real
contra 192.168.72.132): sin -ac, un target que responde igual a
*cualquier* ruta (ej. redirige todo con 302 a /login) hace que ffuf
"encuentre" casi toda la wordlist — en esa ejecución, 29.800 de 29.800
resultados devueltos por ffuf eran ese mismo patrón (302, tamaño entre
284-310 bytes, variando solo porque la respuesta refleja la ruta
pedida). route_patterns generaba pistas sobre cientos de rutas falsas
("wp-admin, visto 289 veces") que en realidad eran ruido.

En vez de recurrir a -ac de ffuf (ya descartado una vez por falso
negativo real: escondió /server-status), se calibra por nuestra
cuenta: se piden 3 rutas inventadas al azar (casi seguro inexistentes)
*antes* de lanzar la wordlist real. Si las tres responden con el mismo
status y, descontando la longitud de la propia ruta inventada, el
mismo tamaño base (±2 bytes) — señal de que el server da la misma
respuesta a cualquier cosa — se descartan de los resultados reales los
que coincidan con ESA firma exacta. Si las tres calibraciones no
coinciden entre sí (comportamiento normal: 404 real, o páginas
distintas por ruta), no se filtra nada.

Riesgo conocido y aceptado: si por pura coincidencia una ruta real
tiene el mismo tamaño base que el catch-all, se descarta igual que con
-ac — pero acotado a una firma medida contra rutas garantizado-falsas,
no a una heurística genérica sobre el resultado real.
"""

import json
import random
import string
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from .. import subprocess_utils

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"

_CALIBRATION_TRIES = 3
_CALIBRATION_TOLERANCE = 2  # bytes de margen en el tamaño base


def _random_path(length: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _probe(web_target, path: str) -> tuple[int, int] | None:
    """Una petición a web_target.base_url/path. Devuelve (status,
    longitud del cuerpo) o None si la petición falla (en cuyo caso no
    se puede calibrar nada — mejor no filtrar que filtrar a ciegas)."""
    url = f"{web_target.base_url}/{path}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.status, len(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, len(e.read())
    except (urllib.error.URLError, OSError):
        return None


def _calibrate_catchall(web_target) -> tuple[int, int] | None:
    """Caracteriza cómo responde web_target a rutas inventadas al azar.
    Devuelve (status, tamaño_base) si las muestras son consistentes
    entre sí (patrón catch-all: todo responde igual) o None si no
    (comportamiento normal, nada que filtrar)."""
    muestras = []
    for _ in range(_CALIBRATION_TRIES):
        path = _random_path(random.randint(10, 20))
        resultado = _probe(web_target, path)
        if resultado is None:
            return None
        status, length = resultado
        muestras.append((status, length - len(path)))

    status0, base0 = muestras[0]
    if all(s == status0 and abs(b - base0) <= _CALIBRATION_TOLERANCE for s, b in muestras):
        return status0, base0
    return None


def _is_catchall_hit(result: dict, calibracion: tuple[int, int]) -> bool:
    status0, base0 = calibracion
    status = result.get("status")
    length = result.get("length")
    path = result.get("url", "").rsplit("/", 1)[-1]
    if status != status0 or length is None:
        return False
    return abs((length - len(path)) - base0) <= _CALIBRATION_TOLERANCE


def fuzz(web_target, wordlist: str = DEFAULT_WORDLIST) -> list[dict]:
    """Ejecuta ffuf contra web_target.base_url y devuelve la lista de
    resultados (uno por ruta que pasó el filtro -fc 404 y no coincide
    con el patrón catch-all calibrado — ver nota arriba), tal cual los
    da su salida -of json. Separado de parse_findings()/parse_urls()
    por el mismo motivo que crawl() en katana_scan.py: la tabla de
    pistas por patrón de ruta (dojohack.route_patterns) reutiliza
    estas mismas rutas sin tener que relanzar el fuzzing. El timeout
    lo controla dojohack.timeouts.run_module, no esta función."""
    if not Path(wordlist).is_file():
        raise RuntimeError(f"wordlist no encontrada: {wordlist}")

    url = f"{web_target.base_url}/FUZZ"

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    try:
        proc = subprocess_utils.run(
            [
                "ffuf", "-u", url, "-w", wordlist,
                "-mc", "all", "-fc", "404",
                "-o", out_path, "-of", "json", "-s",
            ],
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"ffuf devolvió código {proc.returncode}: {proc.stderr[:300]}")

        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)
    finally:
        Path(out_path).unlink(missing_ok=True)

    results = data.get("results", [])

    calibracion = _calibrate_catchall(web_target)
    if calibracion is None:
        return results

    filtrados = [r for r in results if not _is_catchall_hit(r, calibracion)]
    descartados = len(results) - len(filtrados)
    if descartados:
        status0, base0 = calibracion
        print(
            f"[dojohack] ffuf: detectado patrón catch-all (status {status0}, "
            f"~{base0} bytes de base) — {descartados} de {len(results)} resultados "
            f"descartados como ruido. Si tu target responde igual a todo de verdad, "
            f"revisa a mano por si se coló algo real.",
            flush=True,
        )
    return filtrados


def parse_findings(results: list[dict]) -> list[dict]:
    """Convierte los resultados crudos de fuzz() en hallazgos, con el
    mismo convenio que el resto de módulos: {"name", "detail",
    "severity"}."""
    findings = []
    for r in results:
        status = r.get("status")
        length = r.get("length")
        path = r.get("url", "")
        detalle = f"{status} {path} ({length} bytes)"
        findings.append({"name": "FFUF", "detail": detalle, "severity": "info"})
    return findings


def parse_urls(results: list[dict]) -> list[str]:
    """Convierte los resultados crudos de fuzz() en la lista de URLs
    encontradas (sin formatear como hallazgo)."""
    return [r["url"] for r in results if r.get("url")]


def run(web_target, wordlist: str = DEFAULT_WORDLIST) -> list[dict]:
    """Atajo para uso aislado del módulo (pruebas manuales, etc.):
    fuzz() + parse_findings() en un solo paso. cli.py no usa esta
    función directamente porque necesita reutilizar los resultados
    crudos para route_patterns — ver parse_urls()."""
    return parse_findings(fuzz(web_target, wordlist))
