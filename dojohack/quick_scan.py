"""
Modo --quick: diagnóstico rápido antes de lanzar el pipeline completo,
para no relanzar dojohack 2-3 veces cuando el target usa vhosting por
nombre y/o tiene la app real en un subdirectorio — visto de primera
mano el mismo día contra dos labs distintos (academy.thl, aceituno.thl)
(ver conversación con Paco, 2026-10-25).

Se salta nmap (lo lento de verdad: -p- puede tardar hasta 1000s) y
cualquier fuzzing con wordlist (ffuf/vhost_fuzz) — solo un puñado de
peticiones HTTP directas contra la raíz y una lista corta de
subdirectorios de CMS habituales. Pensado para tardar segundos, no
minutos.

No decide nada por Paco ni toca /etc/hosts: solo imprime el
diagnóstico y el comando dojohack "completo" recomendado para copiar/
pegar. El pipeline real (nmap, todas las sondas, etc.) sigue siendo
el único que hace el trabajo de verdad — esto es solo para no
lanzarlo con los parámetros equivocados dos o tres veces.

LIMITACIONES CONOCIDAS (deliberadas, para que esto siga siendo
rápido):
- Solo prueba http/https en el puerto por defecto (80/443) — si la
  app está en un puerto no estándar, esto no lo ve; hace falta el
  nmap completo del pipeline real para eso.
- La lista de subdirectorios es corta y fija (CMS habituales), no el
  wordlist completo de ffuf — si la app vive en una ruta rara que no
  está en la lista, esto no la encuentra y toca seguir a mano.
- El hostname real solo se detecta si WordPress se delata a sí mismo
  (ver vhost_check._find_wordpress_hostname) — para otros CMS, o sin
  CMS de por medio, esto solo avisa de que "huele a vhost", sin poder
  decir el nombre.
"""

import random
import string

import httpx

from . import vhost_check

_COMMON_SUBDIRS = ["wordpress", "wp", "blog", "cms", "app", "site", "web", "admin"]
_TIMEOUT = 6


def _qlog(msg: str) -> None:
    print(f"[dojohack --quick] {msg}", flush=True)


def _try_schemes(target: str) -> tuple[str, httpx.Response] | None:
    """Intenta http y luego https contra la raíz de target (http
    primero: es lo que se ha visto en todos los labs de Paco hasta
    ahora). Devuelve (base_url, response) del primero que responda, o
    None si ninguno de los dos responde. verify=False porque los labs
    de práctica suelen llevar certificados autofirmados."""
    for scheme in ("http", "https"):
        base_url = f"{scheme}://{target}"
        try:
            with httpx.Client(timeout=_TIMEOUT, verify=False) as client:
                return base_url, client.get(base_url)
        except httpx.HTTPError:
            continue
    return None


def _calibrate_catchall(client: httpx.Client, base_url: str) -> tuple[int, int] | None:
    """Mismo truco que ffuf_scan._calibrate_catchall, en miniatura:
    pide dos rutas inventadas al azar (casi seguro inexistentes) y, si
    responden con el mismo status y tamaño, es que el servidor
    contesta igual a cualquier cosa (p.ej. WordPress sirviendo un
    "nada encontrado" con 200 en vez de un 404 real) — sin esto, un
    catch-all haría que _probe_subdirs "encontrara" las 8 rutas de la
    lista por igual, un resultado inútil."""
    muestras = []
    for _ in range(2):
        path = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        try:
            resp = client.get(f"{base_url}/{path}")
        except httpx.HTTPError:
            return None
        muestras.append((resp.status_code, len(resp.content)))
    if muestras[0] == muestras[1]:
        return muestras[0]
    return None


def _probe_subdirs(base_url: str) -> list[tuple[str, int]]:
    """Comprueba la lista corta de subrutas típicas de CMS (una GET
    cada una, sin seguir redirects — un 301 ya es señal suficiente).
    Devuelve (ruta, status) de las que no son 404 y no coinciden con
    el patrón catch-all calibrado (ver _calibrate_catchall)."""
    with httpx.Client(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
        catchall = _calibrate_catchall(client, base_url)
        encontrados = []
        for sub in _COMMON_SUBDIRS:
            try:
                resp = client.get(f"{base_url}/{sub}")
            except httpx.HTTPError:
                continue
            if resp.status_code == 404:
                continue
            if catchall and (resp.status_code, len(resp.content)) == catchall:
                continue
            encontrados.append((sub, resp.status_code))
    return encontrados


def run(target: str) -> None:
    """Imprime el diagnóstico rápido y el comando dojohack completo
    recomendado. No devuelve nada que cli.py necesite usar — cli.py
    sale justo después de llamar a esto cuando se pasa --quick."""
    _qlog(f"sondeando {target}...")

    resultado = _try_schemes(target)
    if resultado is None:
        _qlog(f"{target} no responde por http ni https — nada que diagnosticar.")
        return
    base_url, _ = resultado

    info = vhost_check.probe(base_url)
    señales = info["default_page_signals"] if info else []
    wp_hostname = info["wp_hostname"] if info else None
    hostname_real = wp_hostname and wp_hostname != target and not vhost_check.is_ip(wp_hostname)

    if hostname_real:
        _qlog(f"vhost: sí — hostname real detectado: {wp_hostname} (vía WordPress/wp-json)")
    elif señales:
        _qlog(f"vhost: probablemente sí — {'; '.join(señales)}, pero no se pudo adivinar el hostname real.")
    else:
        _qlog("vhost: no se detecta nada raro, probar con el target tal cual debería ir bien.")

    subdirs = _probe_subdirs(base_url)
    if subdirs:
        rutas = ", ".join(f"/{s} ({c})" for s, c in subdirs)
        _qlog(f"posible CMS en subdirectorio: {rutas}")

    target_recomendado = wp_hostname if hostname_real else target
    partes = ["dojohack", target_recomendado]
    if subdirs:
        partes += ["--base-path", f"/{subdirs[0][0]}"]
    if not vhost_check.is_ip(target_recomendado):
        partes += ["--name", target_recomendado.split(".")[0]]
    _qlog("comando recomendado:\n  " + " ".join(partes))

    if hostname_real:
        _qlog(f"nota: añade primero '{wp_hostname}' a /etc/hosts si no está ya — dojohack no lo toca por ti.")
