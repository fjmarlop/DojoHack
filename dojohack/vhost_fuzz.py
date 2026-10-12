"""
Fuzzing automático de vhost. Cuando dojohack.vhost_check.check() avisa
de que target huele a vhost por defecto, esto intenta encontrar el
hostname real probando una wordlist de nombres habituales como
cabecera Host — en vez de que haga falta repetir a mano el fuzzing que
hizo falta la primera vez que pasó esto (contra 192.168.72.134,
aunque resultó ser un caso de subdirectorio, no de vhost — y antes
contra casapaco.thl, donde sí era vhosting de verdad).

Usa ffuf (ya en el arsenal, con su propio modo de fuzzing de
cabeceras: -H "Host: FUZZ") en vez de un binario nuevo — mismo patrón
que el resto del proyecto: una herramienta, muchos usos.

Se calibra con una sola petición de referencia (sin Host forzado) y se
descarta esa talla exacta con -fs — mismo principio que el filtro anti
catch-all de ffuf_scan.py, pero aquí lo que se busca es justo lo
contrario de lo que allí se descartaba: una respuesta DISTINTA a la
página por defecto es la señal de que se encontró el vhost real.

LIMITACIÓN CONOCIDA: solo prueba palabras sueltas (admin, dev, blog,
wordpress...), no FQDNs con una TLD inventada. No hay forma de
adivinar una convención de nombres propia (como ".thl") sin alguna
pista externa — certificado TLS, /etc/hosts, la descripción del reto.
Si --base-path ya resolvió el problema real (como pasó con
192.168.72.134), esto simplemente no encontrará nada, que es lo
correcto: no hay ningún vhost que encontrar.
"""

import dataclasses
import json
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from . import subprocess_utils

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"


def _baseline_size(base_url: str) -> int | None:
    try:
        with urllib.request.urlopen(f"{base_url}/", timeout=10) as resp:
            return len(resp.read())
    except urllib.error.HTTPError as e:
        return len(e.read())
    except (urllib.error.URLError, OSError):
        return None


def fuzz(web_target, wordlist: str = DEFAULT_WORDLIST) -> list[str]:
    """Prueba cada palabra de wordlist como cabecera Host contra la
    raíz de web_target (ignora base_path — mismo motivo que
    vhost_check.check(): esto comprueba vhosts del servidor, no
    subdirectorios de una app concreta). Devuelve los nombres cuya
    respuesta tiene un tamaño distinto al de la respuesta por defecto
    (candidatos a hostname real) — vacía si no hay wordlist, no
    responde, o todos dan el mismo tamaño que la página por defecto."""
    if not Path(wordlist).is_file():
        return []

    base = dataclasses.replace(web_target, base_path="").base_url

    baseline_size = _baseline_size(base)
    if baseline_size is None:
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    try:
        proc = subprocess_utils.run(
            [
                "ffuf", "-u", f"{base}/", "-H", "Host: FUZZ", "-w", wordlist,
                "-fs", str(baseline_size), "-mc", "all",
                "-o", out_path, "-of", "json", "-s",
            ],
            text=True,
        )
        if proc.returncode != 0:
            return []
        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    finally:
        Path(out_path).unlink(missing_ok=True)

    return sorted({r["host"] for r in data.get("results", []) if r.get("host")})
