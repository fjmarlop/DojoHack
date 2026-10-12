"""
Módulo enum4linux-ng — enumeración de SMB/LDAP (sistemas Windows y
Samba). Igual que el resto: binario externo, cero lógica propia de
detección que reescribir en clean-room.

Solo tiene sentido cuando nmap ya vio SMB (139/445) o LDAP (389/636)
abiertos — cli.py lo gatea así, no se lanza a ciegas en cada pasada:
sería tiempo tirado en los labs Linux-only vistos hasta ahora (ninguno
tenía SMB), y "arsenal completo" no significa ignorar lo que nmap ya
sabe sobre si hay algo que enumerar.

LIMITACIÓN CONOCIDA: el formato exacto del JSON cuando SÍ hay una
sesión SMB/LDAP válida (os_info/users/groups/shares/policy con datos
reales) no se ha podido validar todavía contra un lab real — ninguno
de los labs probados hasta ahora expone SMB. Solo se confirmó el caso
"nada accesible" (listeners.*.accessible = false para los cuatro
puertos). Por eso el parseo no cablea nombres de campo concretos para
esas secciones: en vez de arriesgarse a desalinearse con la estructura
real y perder datos en silencio, cada sección no vacía del JSON se
vuelca tal cual (como texto) en su propio hallazgo. Menos pulido que
una plantilla por campo, pero correcto independientemente de cómo
esté estructurada por dentro — a revisar en cuanto aparezca un lab con
SMB de verdad.
"""

import json
import tempfile
from pathlib import Path

from .. import subprocess_utils

# Claves de "contabilidad" del propio enum4linux-ng, sin valor de
# reconocimiento por sí mismas (confirmado contra un target sin
# SMB/LDAP accesible) — se ignoran al volcar el resto de secciones.
_CLAVES_IGNORADAS = {"target", "credentials", "listeners", "errors"}


def run(target: str) -> list[dict]:
    """Devuelve una lista de hallazgos con el mismo convenio que el
    resto de módulos: {"name", "detail", "severity"}. El timeout lo
    controla dojohack.timeouts.run_module, no esta función."""
    with tempfile.TemporaryDirectory() as tmpdir:
        prefix = str(Path(tmpdir) / "e4l")
        proc = subprocess_utils.run(
            ["enum4linux-ng", "-A", target, "-oJ", prefix],
            text=True,
        )
        json_path = Path(f"{prefix}.json")
        if not json_path.is_file():
            if proc.returncode != 0:
                raise RuntimeError(f"enum4linux-ng devolvió código {proc.returncode}: {proc.stderr[:300]}")
            return []
        data = json.loads(json_path.read_text(encoding="utf-8"))

    listeners = data.get("listeners") or {}
    if not any(isinstance(v, dict) and v.get("accessible") for v in listeners.values()):
        return []  # ni SMB ni LDAP accesibles: nada que enumerar, no es un fallo

    findings = []
    for seccion, contenido in data.items():
        if seccion in _CLAVES_IGNORADAS or not contenido:
            continue
        findings.append({
            "name": "ENUM4LINUX",
            "detail": f"{seccion}: {json.dumps(contenido, ensure_ascii=False)[:400]}",
            "severity": "info",
        })

    return findings
