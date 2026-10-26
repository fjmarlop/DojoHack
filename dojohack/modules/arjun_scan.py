"""
Módulo arjun — descubrimiento de parámetros ocultos. Igual que el
resto: binario externo, cero lógica propia de detección que
reescribir en clean-room.

Hueco que destapó el propio pipeline contra un lab real: dalfox
encontró un XSS reflejado en el parámetro 's' de WordPress por su
propio mining interno de parámetros, pero route_patterns y las sondas
propias (ssti/ssrf/path_traversal/sqli/command_injection) se quedaron
con 0 puntos de inyección sobre ese mismo endpoint — katana solo ve
parámetros que aparecen en enlaces/formularios visibles, y 's' no
estaba en ninguno. Arjun encuentra ese tipo de parámetro aunque no
esté enlazado en ningún sitio, probando una wordlist de nombres
habituales contra cada URL (confirmado contra el lab real: encontró
26, incluido 's', contra la raíz de /wordpress/).

Se ejecuta contra las mismas URLs que ya rastreó katana (mismo
acoplamiento que dalfox — ver katana_scan.py), no solo contra la raíz:
un parámetro oculto puede vivir en cualquier endpoint, no solo en el
principal. Una invocación de arjun por URL — no tiene un modo de
fichero de salida único combinando varias URLs que sirva para esto.

Si arjun no encuentra ningún parámetro para una URL, no escribe
fichero de salida (confirmado contra el lab real) — se trata igual
que "nada que reportar para esa URL", no como un fallo.

Los resultados se devuelven también como puntos de inyección (mismo
formato que dojohack.probes.common) para que cli.py pueda sumarlos a
los que ya aportan katana/route_patterns antes de pasárselos a las
sondas propias — ver parse_injection_points().

Una invocación de arjun por URL, EN PARALELO (pool moderado — cada
llamada es un subproceso de verdad, no solo una petición HTTP, así
que no conviene tantos a la vez como en las sondas propias, ver
probes/concurrency.py). Visto de primera mano contra un lab real
(aceituno.thl, 91 endpoints): uno detrás de otro se comía con
facilidad cualquier tope pensado como presupuesto total (ver
conversación con Paco, 2026-10-25/26). `timeout` aquí es el tope POR
URL (se propaga a subprocess_utils.run()), no un presupuesto global
— con un pool de MAX_WORKERS, el techo real para toda la pasada es
aproximadamente timeout * ceil(len(urls) / MAX_WORKERS).
"""

import json
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .. import subprocess_utils

MAX_WORKERS = 8


def _discover_one(url: str, timeout: int | None) -> tuple[str, list[str]] | None:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = Path(tmp.name)
    try:
        subprocess_utils.run(["arjun", "-u", url, "-o", str(out_path), "-q"], text=True, timeout=timeout)
        if not out_path.is_file() or out_path.stat().st_size == 0:
            return None
        data = json.loads(out_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return None
    finally:
        out_path.unlink(missing_ok=True)

    entry = data.get(url) or next(iter(data.values()), {})
    params = entry.get("params") or []
    return (url, params) if params else None


def discover(urls: list[str], timeout: int | None = None) -> dict[str, list[str]]:
    """Ejecuta arjun contra cada URL (en paralelo, ver nota arriba) y
    devuelve {url: [parámetros encontrados]} (solo para las URLs
    donde encontró algo)."""
    resultados: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_discover_one, url, timeout): url for url in urls}
        for future in as_completed(futures):
            resultado = future.result()
            if resultado:
                url, params = resultado
                resultados[url] = params
    return resultados


def parse_findings(discovered: dict[str, list[str]]) -> list[dict]:
    """Convierte discover() en hallazgos, con el mismo convenio que el
    resto de módulos: {"name", "detail", "severity"}."""
    findings = []
    for url, params in discovered.items():
        findings.append({
            "name": "ARJUN",
            "detail": f"{url} — parámetros ocultos encontrados: {', '.join(params)}",
            "severity": "info",
        })
    return findings


def parse_injection_points(discovered: dict[str, list[str]]) -> list[dict]:
    """Un punto de inyección GET por cada (url, parámetro) que
    encontró arjun, mismo formato que dojohack.probes.common — para
    que las sondas propias también los prueben, no solo quedarse como
    hallazgo informativo."""
    points = []
    for url, params in discovered.items():
        for param in params:
            points.append({
                "method": "GET", "url": url,
                "param": param, "params": {param: "1"},
            })
    return points
