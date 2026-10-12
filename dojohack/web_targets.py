"""
Resolución de "dónde está la app web de verdad" a partir de lo que ya
descubrió nmap, en vez de asumir siempre http://target/ en el puerto
80 — el supuesto que tenían ffuf/katana/dalfox/trufflehog/vhost_check
hasta ahora.

Dos labs reales seguidos destaparon el problema por dos lados
distintos:
- casapaco.thl: la app real estaba detrás de virtual hosting por
  nombre (vhost_check ya lo cubre, pero seguía asumiendo el puerto 80).
- 192.168.72.134: la app real (WordPress) estaba en un subdirectorio
  (/wordpress), no en la raíz — ffuf ya la encontró por casualidad
  fuzzing directorios, pero ningún otro módulo sabía mirar ahí.

Y dos casos más que no se han visto todavía en estos labs pero son
igual de plausibles en otros: la app en un puerto que no es el 80
(nmap ya lo sabría por el nombre de servicio, pero nadie lo usaba), o
servida solo por HTTPS.

Este módulo no intenta adivinar el subdirectorio (eso sigue siendo
cosa de Paco, o de lo que descubra ffuf) — solo evita que el pipeline
de por hecho el puerto/esquema cuando nmap ya tiene mejor información,
y deja un sitio único para fijar la ruta base a mano (--base-path) una
vez que se sabe cuál es.
"""

import re
from dataclasses import dataclass

_PORT_RE = re.compile(r"^(\d+)/(tcp|udp) open (\S+)")


@dataclass(frozen=True)
class WebTarget:
    scheme: str  # "http" o "https"
    host: str
    port: int
    base_path: str = ""  # "" o algo como "/wordpress" (sin barra final)

    @property
    def base_url(self) -> str:
        es_puerto_por_defecto = (self.scheme, self.port) in (("http", 80), ("https", 443))
        puerto = "" if es_puerto_por_defecto else f":{self.port}"
        return f"{self.scheme}://{self.host}{puerto}{self.base_path}"


def _normalize_base_path(base_path: str | None) -> str:
    if not base_path:
        return ""
    base_path = base_path.strip()
    if not base_path.startswith("/"):
        base_path = "/" + base_path
    return base_path.rstrip("/")


def _scheme_for_service(svc_name: str) -> str | None:
    svc_name = svc_name.lower()
    if "https" in svc_name or svc_name.startswith("ssl/") or "ssl" in svc_name:
        return "https"
    if "http" in svc_name:
        return "http"
    return None


def resolve_from_nmap(
    host: str, port_findings: list[dict], base_path: str | None = None
) -> list[WebTarget]:
    """A partir de los hallazgos PORT que ya produjo nmap_scan, devuelve
    los targets web candidatos (uno por puerto que nmap etiquetó como
    http/https/ssl). Si no hay ninguno (nmap se omitió, falló, o no
    encontró nada que huela a web), cae al viejo supuesto de siempre:
    http en el puerto 80 — para no dejar el pipeline sin nada que
    escanear. base_path se aplica igual a todos los targets resueltos:
    se asume una sola app, pensada para avisar de ella a mano una vez
    que se sabe dónde está (ver route_patterns/ffuf, que es como se
    suele descubrir)."""
    base_path = _normalize_base_path(base_path)

    targets = []
    for f in port_findings or []:
        if f.get("name") != "PORT":
            continue
        m = _PORT_RE.match(f.get("detail", ""))
        if not m:
            continue
        portid, protocol, svc_name = m.groups()
        if protocol != "tcp":
            continue
        scheme = _scheme_for_service(svc_name)
        if scheme is None:
            continue
        targets.append(WebTarget(scheme=scheme, host=host, port=int(portid), base_path=base_path))

    if not targets:
        targets = [WebTarget(scheme="http", host=host, port=80, base_path=base_path)]

    return targets
