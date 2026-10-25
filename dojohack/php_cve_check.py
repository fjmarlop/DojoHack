"""
Detector de CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell") — par de
bugs de memoria internos de PHP: un mal manejo de out-of-memory deja
memoria de la request sin inicializar antes de una reserva posterior,
y un use-after-free hace que esa memoria liberada se reutilice en una
request posterior del mismo worker. Varias estrategias de agotar
memoria pueden disparar esto de forma consistente y llegar a RCE.
CVSS v4.0 9.2 (crítico). Disclosure 2026-10-21. Afecta PHP 7.3 hasta
8.5.11 — prácticamente cualquier instalación no parcheada en los
últimos días, lo que incluye casi cualquier WordPress/app PHP de un
lab de CTF. Advisory oficial de PHP Group: GHSA-w8hw-w9fx-j79w /
GHSA-6wmf-4rv5-p3rp — confirmado de forma independiente en el NVD
(no solo en lo que diga ningún repo de terceros) antes de escribir
esto.

Paco encontró un repo de terceros que detecta esto mismo
(github.com/Masriyan/php2shell) — se leyó su código para confirmar
que es puramente detection-only (fingerprint de versión, sin payload
ni ejecución), pero esta detección se escribe desde cero contra el
advisory público, sin depender de ese repo: es nuevo, de un solo
autor, sin el recorrido de confianza de nmap/ffuf/wpscan/etc. que ya
están en el pipeline (ver conversación con Paco, 2026-10-25, y
CLAUDE.md sobre dependencias de terceros).

Ambos CVEs son bugs internos de memoria sin un "disparador" booleano
seguro: intentar provocar de verdad el OOM/UAF tiende a tirar el
worker de PHP, y eso ya sería empezar a explotar, no dar una pista
(ver CLAUDE.md). Por eso esto se queda en fingerprint de versión +
comparación contra los builds corregidos — una versión vulnerable es
EXPOSICIÓN, nunca prueba de que aquí se pueda explotar de verdad.

Dos técnicas, ambas pasivas/no destructivas:
1. Cabeceras Server / X-Powered-By (si expose_php está activo).
2. Si la cabecera no da la versión: el "egg" de créditos de PHP
   (?=PHPE9568F34-D428-11d2-A769-00AA001ACF42) — truco público de
   PHP con más de 20 años, documentado en incontables advisories de
   seguridad (conocimiento público, no algo sacado del repo de
   terceros): una GET inocua que devuelve una página de créditos
   cuyas cabeceras sí llevan la versión real.

No se correla contra CISA KEV / FIRST EPSS (sí lo hace el repo de
Paco): esa señal sirve para priorizar riesgo en una auditoría real
contra un porfolio de hosts — en un lab de práctica no cambia la
pista, solo añadiría una llamada de red más sin aportar nada.
"""

import re

import httpx

TIMEOUT = 10
EGG_QUERY = "?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"

CVES = "CVE-2026-109618 / CVE-2026-109619 (\"PHP2Shell\")"

# Primer build corregido por rama, según el advisory oficial de PHP
# Group (confirmado en el NVD). Ramas <= EOL_CEILING son EOL:
# vulnerables sin parche oficial — la única mitigación es
# session.upload_progress.enabled=0 + reiniciar los workers de PHP,
# no hay versión a la que "subir" dentro de esas ramas.
FIXED_VERSIONS: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
EOL_CEILING = (8, 1)

_VERSION_RE = re.compile(r"PHP/(\d+\.\d+\.\d+)", re.I)
_PHP_PRESENT_RE = re.compile(r"\bPHP\b|PHPSESSID", re.I)


def _extract_version(headers) -> str | None:
    for name in ("x-powered-by", "server"):
        m = _VERSION_RE.search(headers.get(name, ""))
        if m:
            return m.group(1)
    return None


def _php_present(headers, body: str) -> bool:
    blob = " ".join(headers.get(h, "") for h in ("server", "x-powered-by", "set-cookie"))
    if _PHP_PRESENT_RE.search(blob):
        return True
    return ".php" in body.lower()


def _assess(version: str) -> tuple[str, str] | None:
    """(status, mensaje) a partir de "X.Y.Z", o None si la versión
    queda fuera de lo que cubre el advisory (anterior a 5.4, o una
    rama más nueva de la que no hay datos todavía)."""
    partes = version.split(".")
    if len(partes) != 3 or not all(p.isdigit() for p in partes):
        return None
    major, minor, patch = (int(p) for p in partes)
    if major < 5 or (major == 5 and minor < 4):
        return None

    branch = (major, minor)
    if branch <= EOL_CEILING:
        return "vulnerable", f"PHP {version} está en una rama EOL sin parche oficial para {CVES}"

    fixed = FIXED_VERSIONS.get(branch)
    if fixed is None:
        return None

    if (major, minor, patch) >= fixed:
        return "patched", f"PHP {version} ya tiene el build corregido de {CVES} para esta rama"
    return "vulnerable", (
        f"PHP {version} es anterior al build corregido {'.'.join(map(str, fixed))} para {CVES}"
    )


def check(web_target) -> list[dict]:
    """Hace una petición pasiva (y, si no revela versión, una query
    del 'egg' de créditos de PHP) contra web_target.base_url y
    compara la versión detectada contra los builds corregidos de
    CVE-2026-109618/109619. Un hallazgo como mucho — nada que decir
    si no hay PHP detrás. El timeout lo controla
    dojohack.timeouts.run_module, no esta función."""
    try:
        with httpx.Client(follow_redirects=True, timeout=TIMEOUT) as client:
            resp = client.get(web_target.base_url)
            version = _extract_version(resp.headers)
            present = _php_present(resp.headers, resp.text)

            if version is None:
                try:
                    egg = client.get(web_target.base_url.rstrip("/") + "/" + EGG_QUERY)
                    egg_version = _extract_version(egg.headers)
                    if egg_version:
                        version = egg_version
                        present = True
                except httpx.HTTPError:
                    pass
    except httpx.HTTPError:
        return []

    if not present:
        return []

    if version is None:
        return [{
            "name": "PHP_CVE_CHECK",
            "detail": (
                f"se detecta PHP pero la versión está oculta (expose_php "
                f"desactivado o cabecera recortada) — no se puede comprobar "
                f"exposición a {CVES} sin la versión real."
            ),
            "severity": "info",
        }]

    resultado = _assess(version)
    if resultado is None:
        return []

    status, mensaje = resultado
    severidad = "critical" if status == "vulnerable" else "info"
    return [{"name": "PHP_CVE_CHECK", "detail": mensaje, "severity": severidad}]
