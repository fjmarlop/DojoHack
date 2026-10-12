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

Se calibra con dos peticiones de referencia usando un Host claramente
inventado (al azar, no "sin cabecera Host") y se descarta esa talla
exacta con -fs — mismo principio que el filtro anti catch-all de
ffuf_scan.py, pero aquí lo que se busca es justo lo contrario de lo
que allí se descartaba: una respuesta DISTINTA a la página por
defecto es la señal de que se encontró el vhost real.

Importante: contra un lab real hay DOS clases distintas de "esto no es
un vhost real", no una sola:
1. Host no reconocido pero sintácticamente normal (ej. "blog",
   "admin", una cadena aleatoria) → el vhost por defecto de Apache,
   200 con el tamaño que se calibra aquí.
2. Host puramente numérico o de alguna forma inválido (ej. "1", "100",
   "www.1") → Apache responde 400 Bad Request (su propia página de
   error genérica, un tamaño fijo distinto) ANTES de llegar siquiera a
   elegir vhost. Calibrar solo contra la clase 1 (como se hacía antes
   de este ajuste) deja pasar cualquier Host de la clase 2 como falso
   "candidato" — confirmado: ~40 candidatos falsos contra un lab real,
   todos Hosts numéricos de la wordlist. Por eso fuzz() también
   descarta explícitamente el status 400 (nunca es un vhost real: si
   lo fuera, no le daría Bad Request a su propio nombre correcto).

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
import random
import string
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from . import subprocess_utils

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"


def _random_host(length: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _baseline_size(base_url: str, tries: int = 2) -> int | None:
    """Tamaño de la respuesta a un Host claramente inventado (no la
    ausencia de cabecera Host — ver nota del módulo). Si dos intentos
    con nombres distintos no coinciden en talla, no se puede calibrar
    con fiabilidad y se devuelve None (mejor no filtrar nada que
    filtrar mal)."""
    tallas = set()
    for _ in range(tries):
        host = _random_host()
        try:
            req = urllib.request.Request(f"{base_url}/", headers={"Host": host})
            with urllib.request.urlopen(req, timeout=10) as resp:
                tallas.add(len(resp.read()))
        except urllib.error.HTTPError as e:
            tallas.add(len(e.read()))
        except (urllib.error.URLError, OSError):
            return None
    return tallas.pop() if len(tallas) == 1 else None


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
                "-fs", str(baseline_size), "-fc", "400", "-mc", "all",
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
