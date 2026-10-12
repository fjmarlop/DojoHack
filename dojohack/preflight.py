"""
Preflight — comprueba que el arsenal completo de binarios externos
está instalado antes de arrancar el pipeline, e intenta instalarlo
vía apt si falta algo.

Se ejecuta una sola vez al principio de cli.py, no módulo a módulo:
así, si hace falta sudo, se pide la contraseña una sola vez al
arrancar — no a mitad de un escaneo largo, cuando le toque el turno
al módulo que lo necesita.

La instalación automática necesita sudo interactivo (para teclear la
contraseña) — pensado para cuando Paco lanza `dojohack <target>`
directamente en su terminal real, con TTY. Si se ejecuta sin TTY
(p.ej. encadenado desde otro proceso) sudo fallará solo, y se avisa
con el comando exacto para instalarlo a mano, sin colgar el pipeline.
"""

import shutil
import subprocess
import sys

REQUIRED_TOOLS = {
    "nmap": "nmap",
    "nuclei": "nuclei",
    "ffuf": "ffuf",
    "katana": "katana",
    "dalfox": "dalfox",
    "trufflehog": "trufflehog",
    "wpscan": "wpscan",
    "enum4linux-ng": "enum4linux-ng",
    "arjun": "arjun",
    "testssl": "testssl.sh",  # binario se llama "testssl", el paquete de apt es "testssl.sh"
}


def check_and_install() -> list[str]:
    """Comprueba cada binario de REQUIRED_TOOLS. Si falta alguno,
    intenta instalarlo con `sudo apt-get install -y` (todos juntos,
    una sola llamada). Devuelve la lista de binarios que SIGUEN sin
    estar disponibles después del intento (vacía si todo está listo),
    para que cli.py pueda saltarse sus módulos correspondientes."""
    missing = sorted(tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None)
    if not missing:
        return []

    pkgs = [REQUIRED_TOOLS[tool] for tool in missing]
    print(
        f"[dojohack] faltan herramientas: {', '.join(missing)} — intentando instalar...",
        file=sys.stderr,
    )
    try:
        subprocess.run(["sudo", "apt-get", "install", "-y", *pkgs], check=False)
    except FileNotFoundError:
        pass  # no hay sudo/apt-get en este sistema (no debería pasar en Kali)

    still_missing = sorted(tool for tool in missing if shutil.which(tool) is None)
    if still_missing:
        manual_pkgs = " ".join(REQUIRED_TOOLS[t] for t in still_missing)
        print(
            f"[dojohack] no se pudieron instalar automáticamente: "
            f"{', '.join(still_missing)}. Sus módulos se omiten en esta pasada.\n"
            f"[dojohack] instálalas a mano con: sudo apt-get install -y {manual_pkgs}",
            file=sys.stderr,
        )
    return still_missing
