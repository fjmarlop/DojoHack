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

from . import classifier, preflight, preprocessor, report, route_patterns
from .modules import dalfox_scan, ffuf_scan, katana_scan, nmap_scan, nuclei_scan, trufflehog_scan
from .probes import common as probe_common
from .probes import path_traversal, ssrf, ssti
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

    ffuf_urls: list = []
    if "ffuf" in missing_tools:
        log("ffuf: omitido (binario no encontrado)")
    else:
        log("ffuf: en marcha...")
        ffuf_results = run_module(
            ffuf_scan.fuzz, target,
            timeout=MODULE_TIMEOUTS["ffuf"], label="ffuf", on_error=log,
        )
        if ffuf_results:
            result = ffuf_scan.parse_findings(ffuf_results)
            ffuf_urls = ffuf_scan.parse_urls(ffuf_results)
            findings.extend(result)
            log(f"ffuf: hecho — {len(result)} rutas encontradas")
        else:
            log("ffuf: sin resultado (fallo, timeout o nada que reportar)")

    katana_urls: list = []
    katana_forms: list = []
    if "katana" in missing_tools:
        log("katana: omitido (binario no encontrado)")
    else:
        log("katana: en marcha...")
        raw = run_module(
            katana_scan.crawl, target,
            timeout=MODULE_TIMEOUTS["katana"], label="katana", on_error=log,
        )
        if raw:
            result = katana_scan.parse_findings(raw)
            katana_urls = katana_scan.parse_endpoints(raw)
            katana_forms = katana_scan.parse_forms(raw)
            findings.extend(result)
            log(f"katana: hecho — {len(result)} endpoints encontrados")
        else:
            log("katana: sin resultado (fallo, timeout o nada que reportar)")

    rutas_descubiertas = ffuf_urls + katana_urls
    result = route_patterns.scan_paths(rutas_descubiertas)
    if result:
        findings.extend(result)
    log(f"patrones de ruta: {len(result)} rutas sospechosas de {len(rutas_descubiertas)} analizadas")

    if "dalfox" in missing_tools:
        log("dalfox: omitido (binario no encontrado)")
    else:
        log("dalfox: en marcha...")
        result = run_module(
            dalfox_scan.run, target, urls=katana_urls or None,
            timeout=MODULE_TIMEOUTS["dalfox"], label="dalfox", on_error=log,
        )
        if result:
            findings.extend(result)
            log(f"dalfox: hecho — {len(result)} XSS encontrados")
        else:
            log("dalfox: sin resultado (fallo, timeout o nada que reportar)")

    if "trufflehog" in missing_tools:
        log("trufflehog: omitido (binario no encontrado)")
    else:
        log("trufflehog: en marcha...")
        result = run_module(
            trufflehog_scan.run, target,
            timeout=MODULE_TIMEOUTS["trufflehog"], label="trufflehog", on_error=log,
        )
        if result:
            findings.extend(result)
            log(f"trufflehog: hecho — {len(result)} secretos encontrados")
        else:
            log("trufflehog: sin resultado (fallo, timeout, no expone .git, o nada que reportar)")

    injection_points = probe_common.from_urls(katana_urls) + probe_common.from_forms(katana_forms)

    log(f"ssti: en marcha... ({len(injection_points)} puntos de inyección)")
    result = run_module(
        ssti.run, injection_points,
        timeout=MODULE_TIMEOUTS["ssti"], label="ssti", on_error=log,
    )
    if result:
        findings.extend(result)
        log(f"ssti: hecho — {len(result)} hallazgos")
    else:
        log("ssti: sin resultado (fallo, timeout, sin puntos de inyección, o nada que reportar)")

    log(f"ssrf: en marcha... ({len(injection_points)} puntos de inyección)")
    result = run_module(
        ssrf.run, injection_points, target,
        timeout=MODULE_TIMEOUTS["ssrf"], label="ssrf", on_error=log,
    )
    if result:
        findings.extend(result)
        log(f"ssrf: hecho — {len(result)} hallazgos")
    else:
        log("ssrf: sin resultado (fallo, timeout, sin puntos de inyección, o nada que reportar)")

    log(f"path_traversal: en marcha... ({len(injection_points)} puntos de inyección)")
    result = run_module(
        path_traversal.run, injection_points,
        timeout=MODULE_TIMEOUTS["path_traversal"], label="path_traversal", on_error=log,
    )
    if result:
        findings.extend(result)
        log(f"path_traversal: hecho — {len(result)} hallazgos")
    else:
        log("path_traversal: sin resultado (fallo, timeout, sin puntos de inyección, o nada que reportar)")

    out_path = out_dir / "findings.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings}, f, indent=2, ensure_ascii=False)
    log(f"guardado: {out_path}")

    preprocesado = preprocessor.preprocess_findings(findings)
    preprocessed_path = out_dir / "preprocessed.json"
    with open(preprocessed_path, "w", encoding="utf-8") as f:
        json.dump(preprocesado, f, indent=2, ensure_ascii=False)
    log(
        f"preprocesado: {len(preprocesado['grupos'])} grupos, "
        f"{len(preprocesado['ruido'])} descartados como ruido — guardado: {preprocessed_path}"
    )

    pistas = classifier.classify(preprocesado)
    contexto = classifier.extract_context(preprocesado)
    pistas_path = out_dir / "pistas.json"
    with open(pistas_path, "w", encoding="utf-8") as f:
        json.dump({"pistas": pistas, "contexto": contexto}, f, indent=2, ensure_ascii=False)
    log(f"pistas: {len(pistas)} — guardado: {pistas_path}")

    informe_path = out_dir / "informe.md"
    with open(informe_path, "w", encoding="utf-8") as f:
        f.write(report.render_markdown(target, pistas, contexto))
    log(f"informe: guardado: {informe_path}")

    print(report.render_terminal(target, pistas, contexto))

    return 0


if __name__ == "__main__":
    sys.exit(main())
