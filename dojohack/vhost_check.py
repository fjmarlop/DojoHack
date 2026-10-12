"""
Aviso de posible vhost equivocado. Muchos labs de CTF (HTB/THM/
DockerLabs) sirven la app real por virtual hosting de nombre
(Apache/Nginx): si se escanea por IP directa en vez del hostname real,
el `Host:` que ven ffuf/katana/dalfox/nuclei es la IP, no el nombre —
y el servidor cae en el vhost por defecto, que suele ser genérico (una
página de bienvenida, o un catch-all que redirige cualquier ruta) y no
tiene nada que ver con la app del reto.

Visto de primera mano contra casapaco.thl: por IP directa, Apache
devolvía un 302 que además reflejaba sin sanear cualquier parámetro de
query — parecía un hallazgo real (hasta "confirmó" un XSS con dalfox)
pero era puro ruido del vhost por defecto. Escaneando por el hostname
real, 0 reflejados: la app de verdad no tiene ese problema.

Este módulo NO intenta adivinar el hostname real (eso es trabajo de
Paco: /etc/hosts, el SAN de un certificado TLS, nmap --script
http-vhosts, fuzzing de Host...) — solo avisa de que el host huele a
vhost equivocado, antes de que el resto del pipeline se ponga a
redactar pistas sobre una app que no es la real. No bloquea nada
(coherente con "pipeline automático, sin pedir confirmaciones" — ver
CLAUDE.md): solo es una línea más de feedback en vivo.

check() recibe un dojohack.web_targets.WebTarget (no un string suelto)
porque el vhost equivocado puede darse en cualquier puerto/esquema que
nmap haya encontrado, no solo en http/80 — ver web_targets.py.
"""

import dataclasses
import ipaddress
import urllib.error
import urllib.request
import uuid

_DEFAULT_PAGE_SIGNATURES = [
    "Apache2 Debian Default Page",
    "It works!",
    "Welcome to nginx",
    "IIS Windows Server",
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urlopen() sigue los redirects por defecto — y el propio redirect
    (302 a la app real, con el marcador reflejado en el Location) es
    justo la señal que hay que inspeccionar, no algo que seguir hasta
    llegar a la app real. Sin esto, _probe() nunca vería el 302."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _probe(base_url: str) -> str | None:
    """Petición barata a base_url con un parámetro inventado, para
    detectar señales de vhost por defecto. Separado de check() para
    poder probarlo contra un servidor local en un puerto cualquiera
    sin depender de que target sea literalmente una IP en el puerto 80.
    No sigue redirects (ver _NoRedirect) — un 302 es justo lo que hay
    que mirar, no algo que seguir."""
    marker = uuid.uuid4().hex
    url = f"{base_url}/?dojohack_vhost_check={marker}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "dojohack"})
        resp = _OPENER.open(req, timeout=10)
        status = resp.status
        body = resp.read(20000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        # Con _NoRedirect, un 3xx (o cualquier status de error) llega
        # aqui en vez de como respuesta normal — sigue siendo la
        # respuesta real del servidor, solo que urllib la trata como
        # "error" al no haber nadie que siga la redirección.
        status = e.code
        body = e.read(20000).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError):
        return None  # si ni responde por HTTP, no hay vhost que avisar aqui

    señales = []
    if marker in body:
        señales.append(
            "refleja sin sanear un parámetro inventado en la respuesta "
            "(típico de una página por defecto/placeholder, no de una app real)"
        )
    if 300 <= status < 400:
        señales.append(f"responde con un redirect ({status}) a la petición más básica")
    for firma in _DEFAULT_PAGE_SIGNATURES:
        if firma in body:
            señales.append(f"el cuerpo tiene pinta de página por defecto ('{firma}')")
            break

    if not señales:
        return None

    return "; ".join(señales)


def check(web_target) -> str | None:
    """Si web_target.host es una IP, hace una petición barata a la raíz
    de ese esquema/puerto (ver _probe) para detectar señales de vhost
    por defecto. Deliberadamente ignora web_target.base_path — esto
    comprueba el vhost del servidor, no un subdirectorio concreto de
    la app; mezclar las dos cosas podría dar señales contradictorias
    si la raíz y el subdirectorio se comportan distinto.

    Devuelve un mensaje de aviso (para que cli.py lo imprima con
    log()) o None si el host no es una IP, no responde, o no hay nada
    raro que señalar."""
    if not _is_ip(web_target.host):
        return None

    base_url = dataclasses.replace(web_target, base_path="").base_url
    señales = _probe(base_url)
    if not señales:
        return None

    return (
        f"{base_url} apunta a una IP y la respuesta huele a vhost por defecto, "
        f"no a la app real: {señales}. Si el lab usa virtual hosting por "
        f"nombre, ffuf/katana/dalfox/nuclei podrían estar escaneando el vhost "
        f"equivocado sin que el pipeline se dé cuenta. Busca el hostname real "
        f"(certificado TLS, /etc/hosts, nmap --script http-vhosts, fuzzing de "
        f"Host) y relanza dojohack contra ese hostname."
    )
