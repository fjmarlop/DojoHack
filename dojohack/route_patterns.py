"""
Tabla de pistas por patrón de ruta/nombre — segunda fuente de pistas
del proyecto (ver CLAUDE.md: "descubrimiento en bruto por patrón de
ruta/nombre"). A diferencia de los módulos y sondas anteriores, aquí
no hay ninguna evidencia real de nada: ffuf o katana se han limitado
a encontrar un nombre de ruta que, por experiencia, suele estar
asociado a ciertas técnicas — "login.php" sugiere probar SQLi o
fuerza bruta, un ".git" expuesto sugiere bajarlo y mirar el
historial, etc. Nunca confirma nada, solo apunta hacia dónde mirar —
coherente con el resto de pistas del proyecto. No existe en
PocketHacker; se construye desde cero para DojoHack.

La tabla no pretende ser exhaustiva ni es un escáner de vulnerabilidades
por sí misma: es una lista curada de patrones de ruta/nombre
habituales en CTFs y aplicaciones reales, pensada para ampliarse con
el tiempo según lo que se vaya viendo en los labs.
"""

import re

# Caso aparte del resto de la tabla: no sugiere técnicas genéricas por
# el nombre de la ruta, sino que extrae un dato concreto (el nicename
# de autor de WordPress, que casi siempre coincide con un username
# real del sistema) directamente de la URL — visto de primera mano en
# un lab real, donde ese username no salía por ningún otro módulo
# porque wpscan no llegó a enumerarlo y ARJUN (que sí tocó la misma
# URL) nunca se convierte en pista por sí mismo (ver classifier.py).
_AUTHOR_RE = re.compile(r"/author/([^/?#]+)/?", re.I)

# (patrón regex sobre la ruta/nombre completo, técnicas a sugerir)
PATTERNS: list[tuple[re.Pattern, list[str]]] = [
    (
        re.compile(r"(login|signin|sign-in|auth)\b", re.I),
        ["SQLi en el formulario", "fuerza bruta / credenciales por defecto"],
    ),
    (
        re.compile(r"(admin|administrator|manage|dashboard|cpanel|wp-admin)\b", re.I),
        ["fuerza bruta / credenciales por defecto", "bypass de autenticación"],
    ),
    (
        re.compile(r"\.(bak|old|swp|zip|tar|gz|rar|7z|sql)(\?|$)|~$", re.I),
        ["descargar y revisar el contenido (puede llevar código fuente o secretos)"],
    ),
    (
        re.compile(r"\.env(\?|$)|web\.config(\?|$)", re.I),
        ["descargar y revisar el contenido (suele llevar credenciales/configuración)"],
    ),
    (
        re.compile(r"\.git/|\.svn/|\.hg/", re.I),
        ["clonar el repo expuesto y revisar el historial (puede haber secretos en commits viejos)"],
    ),
    (
        re.compile(r"(upload|file-?upload|import)\b", re.I),
        ["subida de fichero sin restricción (posible webshell)", "bypass de validación de extensión/tipo MIME"],
    ),
    (
        re.compile(r"(api|graphql|swagger|openapi\.json)\b", re.I),
        ["explorar endpoints no documentados", "IDOR / control de acceso roto"],
    ),
    (
        re.compile(r"(debug|phpinfo|console|actuator)\b", re.I),
        ["información de depuración expuesta (versiones, rutas internas, variables de entorno)"],
    ),
    (
        re.compile(r"(phpmyadmin|adminer|pgadmin)\b", re.I),
        ["credenciales por defecto", "acceso directo a la base de datos"],
    ),
    (
        re.compile(r"wp-content|wp-json|wp-login\.php", re.I),
        ["WordPress: enumerar plugins/temas y usuarios (wpscan)"],
    ),
    (
        re.compile(r"\.DS_Store(\?|$)|\.log(\?|$)", re.I),
        ["metadatos/logs que pueden filtrar estructura interna o rutas"],
    ),
]


def match(path: str) -> list[str] | None:
    """Devuelve la lista de técnicas sugeridas para una ruta (de
    TODOS los patrones que coincidan, no solo el primero — una ruta
    como "wp-login.php" coincide tanto con el patrón genérico de
    login como con el específico de WordPress, y las dos pistas
    aportan algo distinto), o None si no coincide con ninguno."""
    tecnicas: list[str] = []
    for patron, tecnicas_patron in PATTERNS:
        if patron.search(path):
            for t in tecnicas_patron:
                if t not in tecnicas:
                    tecnicas.append(t)
    return tecnicas or None


def scan_paths(paths: list[str]) -> list[dict]:
    """Devuelve una lista de hallazgos (uno por ruta que coincide con
    algún patrón conocido), con el mismo convenio que el resto de
    módulos: {"name", "detail", "severity"}. Nunca confirma nada —
    solo apunta técnicas a explorar, igual de dubitativo que el resto
    de pistas del proyecto. Una misma ruta puede generar más de un
    hallazgo (ej. una página de autor de WordPress dispara tanto el
    aviso de username filtrado como el genérico de wp-content)."""
    findings = []
    seen = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)

        m = _AUTHOR_RE.search(path)
        if m:
            usuario = m.group(1)
            findings.append({
                "name": "RUTA_SOSPECHOSA",
                "detail": (
                    f"{path} — página de archivo de autor de WordPress: suele "
                    f"filtrar un username real del sistema ('{usuario}'), vale "
                    f"la pena anotarlo para fuerza bruta / credenciales por "
                    f"defecto en wp-login.php."
                ),
                "severity": "info",
            })

        tecnicas = match(path)
        if tecnicas:
            findings.append({
                "name": "RUTA_SOSPECHOSA",
                "detail": (
                    f"{path} — por el nombre, podría valer la pena probar: "
                    f"{', '.join(tecnicas)}."
                ),
                "severity": "info",
            })
    return findings
