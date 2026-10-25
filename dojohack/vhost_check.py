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

Este módulo intenta UNA forma barata de adivinar el hostname real
(ver _find_wordpress_hostname) cuando WordPress se delata a sí mismo
vía wp-json — para lo demás (certificado TLS, /etc/hosts, nmap
--script http-vhosts, fuzzing de Host...) sigue siendo trabajo de
Paco. Solo avisa, antes de que el resto del pipeline se ponga a
redactar pistas sobre una app que no es la real. No bloquea nada
(coherente con "pipeline automático, sin pedir confirmaciones" — ver
CLAUDE.md): solo es una línea más de feedback en vivo.

Importante, visto de primera mano el mismo día contra aceituno.thl:
las firmas de "página por defecto" (_DEFAULT_PAGE_SIGNATURES) NO
cubren este caso — la raíz devolvía WordPress real, no un placeholder
de Apache/Nginx, así que _probe() no encontraba nada raro. El
mismatch solo salió a la luz leyendo a mano la cabecera `Link` de
WordPress (`<http://aceituno.thl/wp-json/>; rel="https://api.w.org/"`,
que WordPress manda siempre con la URL que ÉL tiene configurada como
suya, sin importar por qué nombre/IP se le pida la página) — una
señal totalmente independiente de que la página "parezca" un
placeholder. Por eso _find_wordpress_hostname() se comprueba siempre,
no solo cuando ya hay señales de página por defecto.

check() recibe un dojohack.web_targets.WebTarget (no un string suelto)
porque el vhost equivocado puede darse en cualquier puerto/esquema que
nmap haya encontrado, no solo en http/80 — ver web_targets.py. probe()
es la versión de más bajo nivel (sobre un base_url suelto, sin
WebTarget) que reutiliza el modo --quick (ver quick_scan.py), que
todavía no tiene un WebTarget resuelto en ese punto.
"""

import dataclasses
import ipaddress
import re
import urllib.error
import urllib.request
import uuid

_DEFAULT_PAGE_SIGNATURES = [
    "Apache2 Debian Default Page",
    "It works!",
    "Welcome to nginx",
    "IIS Windows Server",
]

# Cualquier URL con "wp-json" dentro delata el hostname real que
# WordPress tiene configurado (en la cabecera Link, o en el <link
# rel="https://api.w.org/"> del <head> — el orden de los atributos
# cambia entre esas dos formas, así que esto no asume ninguno en
# concreto, solo busca la URL alrededor de "wp-json").
_WP_JSON_URL_RE = re.compile(r'https?://([^/\s"\'<>]+)/[^\s"\'<>]*wp-json', re.I)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urlopen() sigue los redirects por defecto — y el propio redirect
    (302 a la app real, con el marcador reflejado en el Location) es
    justo la señal que hay que inspeccionar, no algo que seguir hasta
    llegar a la app real. Sin esto, _probe() nunca vería el 302."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _find_wordpress_hostname(headers, body: str) -> str | None:
    link_header = headers.get("Link", "") if headers else ""
    for haystack in (link_header, body):
        m = _WP_JSON_URL_RE.search(haystack)
        if m:
            return m.group(1)
    return None


def probe(base_url: str) -> dict | None:
    """Una única petición barata a base_url con un parámetro
    inventado. Devuelve {"default_page_signals": [...],
    "wp_hostname": str | None} o None si ni responde por HTTP.
    Separado de check() para poder probarlo contra un servidor local
    en un puerto cualquiera, y para que el modo --quick
    (quick_scan.py) lo reutilice sobre una URL suelta sin necesitar
    un WebTarget ya resuelto. No sigue redirects (ver _NoRedirect) —
    un 302 es justo lo que hay que mirar, no algo que seguir."""
    marker = uuid.uuid4().hex
    url = f"{base_url}/?dojohack_vhost_check={marker}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "dojohack"})
        resp = _OPENER.open(req, timeout=10)
        status, headers = resp.status, resp.headers
        body = resp.read(20000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        # Con _NoRedirect, un 3xx (o cualquier status de error) llega
        # aqui en vez de como respuesta normal — sigue siendo la
        # respuesta real del servidor, solo que urllib la trata como
        # "error" al no haber nadie que siga la redirección.
        status, headers = e.code, e.headers
        body = e.read(20000).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError):
        return None  # si ni responde por HTTP, no hay nada que avisar aqui

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

    return {
        "default_page_signals": señales,
        "wp_hostname": _find_wordpress_hostname(headers, body),
    }


def check(web_target) -> str | None:
    """Si web_target.host es una IP, hace una petición barata a la raíz
    de ese esquema/puerto (ver probe()) para detectar señales de vhost
    por defecto o un hostname real delatado por WordPress.
    Deliberadamente ignora web_target.base_path — esto comprueba el
    vhost del servidor, no un subdirectorio concreto de la app;
    mezclar las dos cosas podría dar señales contradictorias si la
    raíz y el subdirectorio se comportan distinto.

    Devuelve un mensaje de aviso (para que cli.py lo imprima con
    log()) o None si el host no es una IP, no responde, o no hay nada
    raro que señalar."""
    if not is_ip(web_target.host):
        return None

    base_url = dataclasses.replace(web_target, base_path="").base_url
    info = probe(base_url)
    if info is None:
        return None

    señales, wp_hostname = info["default_page_signals"], info["wp_hostname"]
    if not señales and not (wp_hostname and wp_hostname != web_target.host):
        return None

    if wp_hostname and wp_hostname != web_target.host:
        return (
            f"{base_url} apunta a una IP, pero WordPress delata (vía wp-json) "
            f"que su hostname real configurado es '{wp_hostname}'. Si el lab "
            f"usa virtual hosting por nombre, ffuf/katana/dalfox/nuclei "
            f"podrían estar escaneando el vhost equivocado sin que el "
            f"pipeline se dé cuenta. Añade '{wp_hostname}' a /etc/hosts y "
            f"relanza dojohack contra ese hostname en vez de la IP."
        )

    return (
        f"{base_url} apunta a una IP y la respuesta huele a vhost por defecto, "
        f"no a la app real: {'; '.join(señales)}. Si el lab usa virtual "
        f"hosting por nombre, ffuf/katana/dalfox/nuclei podrían estar "
        f"escaneando el vhost equivocado sin que el pipeline se dé cuenta. "
        f"Busca el hostname real (certificado TLS, /etc/hosts, nmap --script "
        f"http-vhosts, fuzzing de Host) y relanza dojohack contra ese "
        f"hostname."
    )
