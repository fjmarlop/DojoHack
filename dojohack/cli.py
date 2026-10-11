"""
DojoHack — asistente de pistas para practicar CTF.

Uso:
    python -m dojohack.cli <target>

Primer corte: solo el módulo nmap. El objetivo de esta versión no es
dar pistas todavía — es validar que el cableado completo del pipeline
funciona (timeout por módulo, feedback en vivo, guardado en disco)
antes de sumar el resto de módulos y, más adelante, la capa de pistas.
"""

import argparse
import json
import sys
from pathlib import Path

from . import preflight
from .modules import ffuf_scan, nmap_scan, nuclei_scan
from .timeouts import MODULE_TIMEOUTS, run_module


def log(msg: str) -> None:
    print(f"[dojohack] {msg}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(prog="dojohack")
    parser.add_argument("target", help="IP o dominio del reto")
    parser.add_argument(
        "-o", "--output", default=None,
        help="Carpeta de salida (por defecto: ./output/<target>/)",
    )
    args = parser.parse_args()

    target = args.target
    out_dir = Path(args.output) if args.output else Path("output") / target
    out_dir.mkdir(parents=True, exist_ok=True)

    findings: list = []

    log(f"objetivo: {target}")

    missing_tools = preflight.check_and_install()

    if "nmap" in missing_tools:
        log("nmap: omitido (binario no encontrado)")
    else:
        log("nmap: en marcha...")
        result = run_module(
            nmap_scan.run, target,
            timeout=MODULE_TIMEOUTS["nmap"], label="nmap", on_error=log,
        )
        if result:
            findings.extend(result)
            log(f"nmap: hecho — {len(result)} puertos abiertos")
        else:
            log("nmap: sin resultado (fallo o timeout)")

    if "nuclei" in missing_tools:
        log("nuclei: omitido (binario no encontrado)")
    else:
        log("nuclei: en marcha...")
        result = run_module(
            nuclei_scan.run, target,
            timeout=MODULE_TIMEOUTS["nuclei"], label="nuclei", on_error=log,
        )
        if result:
            findings.extend(result)
            log(f"nuclei: hecho — {len(result)} hallazgos")
        else:
            log("nuclei: sin resultado (fallo, timeout o nada que reportar)")

    if "ffuf" in missing_tools:
        log("ffuf: omitido (binario no encontrado)")
    else:
        log("ffuf: en marcha...")
        result = run_module(
            ffuf_scan.run, target,
            timeout=MODULE_TIMEOUTS["ffuf"], label="ffuf", on_error=log,
        )
        if result:
            findings.extend(result)
            log(f"ffuf: hecho — {len(result)} rutas encontradas")
        else:
            log("ffuf: sin resultado (fallo, timeout o nada que reportar)")

    out_path = out_dir / "findings.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings}, f, indent=2, ensure_ascii=False)
    log(f"guardado: {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
