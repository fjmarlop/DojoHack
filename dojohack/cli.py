"""
DojoHack — asistente de pistas para practicar CTF.

Uso:
    dojohack <target> [--base-path /subdir] [--name nombre] [--polish]
    (o, sin instalar vía pip: python -m dojohack.cli <target> ...)

El pipeline corre nmap/nuclei una vez contra el host, y el resto de
módulos (ffuf/katana/dalfox/trufflehog/vhost_check + las sondas
propias) una vez por cada "target web" que resuelva dojohack.web_targets
a partir de lo que nmap encontró — normalmente uno solo (http/80),
pero puede ser más de uno si nmap ve varios puertos http(s), o uno
distinto si --base-path apunta a un subdirectorio (ver web_targets.py:
visto de primera mano con casapaco.thl, detrás de vhosting, y con
192.168.72.134, con la app real en /wordpress en vez de la raíz).

La carpeta de salida por defecto (./output/<target-o-name>/) se ancla
a la raíz del proyecto (_PROJECT_ROOT), no al directorio desde donde
se invoque — para que `dojohack <target>` deje siempre los ficheros en
el mismo sitio aunque se lance como comando instalado (pip install -e
.) desde cualquier carpeta, en vez de depender de haber hecho cd a
este repo primero.
"""

import argparse
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

from . import ai_redact, classifier, preflight, preprocessor, report, route_patterns, vhost_check, vhost_fuzz, web_targets
from .modules import (
    arjun_scan,
    dalfox_scan,
    enum4linux_scan,
    ffuf_scan,
    katana_scan,
    nmap_scan,
    nuclei_scan,
    testssl_scan,
    trufflehog_scan,
    wpscan_scan,
)
from .probes import command_injection, sqli
from .probes import common as probe_common
from .probes import path_traversal, ssrf, ssti
from .timeouts import MODULE_TIMEOUTS, run_module


def log(msg: str) -> None:
    print(f"[dojohack] {msg}", flush=True)


def _scan_web_target(wt, missing_tools: set, multiple: bool) -> list[dict]:
    """Corre ffuf/katana/route_patterns/dalfox/trufflehog/vhost_check +
    las sondas propias contra un único web_target. Separado de main()
    porque esto se repite una vez por cada target web que haya
    resuelto dojohack.web_targets (normalmente uno, puede ser más de
    uno con varios puertos http/https)."""
    prefix = f"[{wt.base_url}] " if multiple else ""

    def wlog(msg, _prefix=prefix):
        log(f"{_prefix}{msg}")

    findings: list = []

    aviso_vhost = vhost_check.check(wt)
    if aviso_vhost:
        wlog(f"⚠️ {aviso_vhost}")
        if "ffuf" not in missing_tools:
            wlog("vhost_fuzz: probando nombres de host habituales para encontrar el vhost real...")
            candidatos = run_module(
                vhost_fuzz.fuzz, wt,
                timeout=MODULE_TIMEOUTS["vhost_fuzz"], label="vhost_fuzz", on_error=wlog,
            )
            if candidatos:
                wlog(f"vhost_fuzz: {len(candidatos)} candidato(s) a hostname real: {', '.join(candidatos)}")
                findings.append({
                    "name": "VHOST_FUZZ",
                    "detail": (
                        f"posible(s) hostname(s) real(es) encontrado(s) fuzzeando la "
                        f"cabecera Host: {', '.join(candidatos)}. Prueba a relanzar "
                        f"dojohack con ese hostname en vez de la IP."
                    ),
                    "severity": "info",
                })
            else:
                wlog("vhost_fuzz: ningún candidato (puede que no sea vhosting, o que el nombre no esté en la wordlist)")

    if wt.scheme != "https":
        wlog("testssl: omitido (no es https)")
    elif "testssl" in missing_tools:
        wlog("testssl: omitido (binario no encontrado)")
    else:
        wlog("testssl: en marcha...")
        result = run_module(
            testssl_scan.run, wt,
            timeout=MODULE_TIMEOUTS["testssl"], label="testssl", on_error=wlog,
        )
        if result:
            findings.extend(result)
            wlog(f"testssl: hecho — {len(result)} hallazgos")
        else:
            wlog("testssl: sin resultado (fallo, timeout, o nada que reportar)")

    ffuf_urls: list = []
    if "ffuf" in missing_tools:
        wlog("ffuf: omitido (binario no encontrado)")
    else:
        wlog("ffuf: en marcha...")
        ffuf_results = run_module(
            ffuf_scan.fuzz, wt,
            timeout=MODULE_TIMEOUTS["ffuf"], label="ffuf", on_error=wlog,
        )
        if ffuf_results:
            result = ffuf_scan.parse_findings(ffuf_results)
            ffuf_urls = ffuf_scan.parse_urls(ffuf_results)
            findings.extend(result)
            wlog(f"ffuf: hecho — {len(result)} rutas encontradas")
        else:
            wlog("ffuf: sin resultado (fallo, timeout o nada que reportar)")

    katana_urls: list = []
    katana_forms: list = []
    if "katana" in missing_tools:
        wlog("katana: omitido (binario no encontrado)")
    else:
        wlog("katana: en marcha...")
        raw = run_module(
            katana_scan.crawl, wt,
            timeout=MODULE_TIMEOUTS["katana"], label="katana", on_error=wlog,
        )
        if raw:
            result = katana_scan.parse_findings(raw)
            katana_urls = katana_scan.parse_endpoints(raw)
            katana_forms = katana_scan.parse_forms(raw)
            findings.extend(result)
            wlog(f"katana: hecho — {len(result)} endpoints encontrados")
        else:
            wlog("katana: sin resultado (fallo, timeout o nada que reportar)")

    rutas_descubiertas = ffuf_urls + katana_urls
    result = route_patterns.scan_paths(rutas_descubiertas)
    if result:
        findings.extend(result)
    wlog(f"patrones de ruta: {len(result)} rutas sospechosas de {len(rutas_descubiertas)} analizadas")

    if "dalfox" in missing_tools:
        wlog("dalfox: omitido (binario no encontrado)")
    else:
        wlog("dalfox: en marcha...")
        result = run_module(
            dalfox_scan.run, wt, urls=katana_urls or None,
            timeout=MODULE_TIMEOUTS["dalfox"], label="dalfox", on_error=wlog,
        )
        if result:
            findings.extend(result)
            wlog(f"dalfox: hecho — {len(result)} XSS encontrados")
        else:
            wlog("dalfox: sin resultado (fallo, timeout o nada que reportar)")

    if "trufflehog" in missing_tools:
        wlog("trufflehog: omitido (binario no encontrado)")
    else:
        wlog("trufflehog: en marcha...")
        result = run_module(
            trufflehog_scan.run, wt,
            timeout=MODULE_TIMEOUTS["trufflehog"], label="trufflehog", on_error=wlog,
        )
        if result:
            findings.extend(result)
            wlog(f"trufflehog: hecho — {len(result)} secretos encontrados")
        else:
            wlog("trufflehog: sin resultado (fallo, timeout, no expone .git, o nada que reportar)")

    if "wpscan" in missing_tools:
        wlog("wpscan: omitido (binario no encontrado)")
    else:
        wlog("wpscan: en marcha...")
        result = run_module(
            wpscan_scan.run, wt,
            timeout=MODULE_TIMEOUTS["wpscan"], label="wpscan", on_error=wlog,
        )
        if result:
            findings.extend(result)
            wlog(f"wpscan: hecho — {len(result)} hallazgos")
        else:
            wlog("wpscan: sin resultado (fallo, timeout, no es WordPress, o nada que reportar)")

    arjun_points: list = []
    if "arjun" in missing_tools:
        wlog("arjun: omitido (binario no encontrado)")
    elif not katana_urls:
        wlog("arjun: omitido (katana no encontró endpoints que probar)")
    else:
        wlog(f"arjun: en marcha... ({len(katana_urls)} endpoints a comprobar)")
        descubiertos = run_module(
            arjun_scan.discover, katana_urls,
            timeout=MODULE_TIMEOUTS["arjun"], label="arjun", on_error=wlog,
        )
        if descubiertos:
            findings.extend(arjun_scan.parse_findings(descubiertos))
            arjun_points = arjun_scan.parse_injection_points(descubiertos)
            wlog(f"arjun: hecho — {sum(len(p) for p in descubiertos.values())} parámetros ocultos en {len(descubiertos)} endpoint(s)")
        else:
            wlog("arjun: sin resultado (fallo, timeout, o ningún parámetro oculto)")

    injection_points = probe_common.from_urls(katana_urls) + probe_common.from_forms(katana_forms) + arjun_points

    wlog(f"ssti: en marcha... ({len(injection_points)} puntos de inyección)")
    result = run_module(
        ssti.run, injection_points,
        timeout=MODULE_TIMEOUTS["ssti"], label="ssti", on_error=wlog,
    )
    if result:
        findings.extend(result)
        wlog(f"ssti: hecho — {len(result)} hallazgos")
    else:
        wlog("ssti: sin resultado (fallo, timeout, sin puntos de inyección, o nada que reportar)")

    wlog(f"ssrf: en marcha... ({len(injection_points)} puntos de inyección)")
    result = run_module(
        ssrf.run, injection_points, wt.host,
        timeout=MODULE_TIMEOUTS["ssrf"], label="ssrf", on_error=wlog,
    )
    if result:
        findings.extend(result)
        wlog(f"ssrf: hecho — {len(result)} hallazgos")
    else:
        wlog("ssrf: sin resultado (fallo, timeout, sin puntos de inyección, o nada que reportar)")

    wlog(f"path_traversal: en marcha... ({len(injection_points)} puntos de inyección)")
    result = run_module(
        path_traversal.run, injection_points,
        timeout=MODULE_TIMEOUTS["path_traversal"], label="path_traversal", on_error=wlog,
    )
    if result:
        findings.extend(result)
        wlog(f"path_traversal: hecho — {len(result)} hallazgos")
    else:
        wlog("path_traversal: sin resultado (fallo, timeout, sin puntos de inyección, o nada que reportar)")

    wlog(f"sqli: en marcha... ({len(injection_points)} puntos de inyección)")
    result = run_module(
        sqli.run, injection_points,
        timeout=MODULE_TIMEOUTS["sqli"], label="sqli", on_error=wlog,
    )
    if result:
        findings.extend(result)
        wlog(f"sqli: hecho — {len(result)} hallazgos")
    else:
        wlog("sqli: sin resultado (fallo, timeout, sin puntos de inyección, o nada que reportar)")

    wlog(f"command_injection: en marcha... ({len(injection_points)} puntos de inyección)")
    result = run_module(
        command_injection.run, injection_points,
        timeout=MODULE_TIMEOUTS["command_injection"], label="command_injection", on_error=wlog,
    )
    if result:
        findings.extend(result)
        wlog(f"command_injection: hecho — {len(result)} hallazgos")
    else:
        wlog("command_injection: sin resultado (fallo, timeout, sin puntos de inyección, o nada que reportar)")

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(prog="dojohack")
    parser.add_argument("target", help="IP o dominio del reto")
    parser.add_argument(
        "-o", "--output", default=None,
        help="Carpeta de salida (por defecto: <raíz del proyecto>/output/<target>/)",
    )
    parser.add_argument(
        "--base-path", default=None,
        help=(
            "Ruta base de la app si no está en la raíz del servidor "
            "(ej. --base-path /wordpress). Se aplica a todos los "
            "puertos web que encuentre nmap — ver dojohack.web_targets."
        ),
    )
    parser.add_argument(
        "--name", default=None,
        help=(
            "Nombre corto de la máquina, para que la carpeta de salida "
            "coincida con la que use el flujo de writeups (ej. "
            "notas/<nombre>/ en ~/ctf) en vez de usar target tal cual "
            "(que puede ser una IP o un hostname largo). Por defecto, "
            "la carpeta de salida es <raíz del proyecto>/output/<target>/."
        ),
    )
    parser.add_argument(
        "--polish", action="store_true",
        help=(
            "Pedir a Claude (CLI local, `claude -p`, sin API de pago) que "
            "mejore la redacción de recon_writeup.md (conectar hallazgos "
            "relacionados, variar el tono) sin cambiar qué cuenta como "
            "hallazgo. Necesita el comando `claude` en PATH — si no está, "
            "o algo falla, cae a la versión determinista sin romper el "
            "pipeline. Apagado por defecto: el pipeline sigue siendo "
            "totalmente determinista/offline salvo que se pida "
            "explícitamente."
        ),
    )
    args = parser.parse_args()

    target = args.target
    out_dir = Path(args.output) if args.output else _PROJECT_ROOT / "output" / (args.name or target)
    out_dir.mkdir(parents=True, exist_ok=True)

    findings: list = []

    log(f"objetivo: {target}")

    missing_tools = preflight.check_and_install()

    port_findings: list = []
    if "nmap" in missing_tools:
        log("nmap: omitido (binario no encontrado)")
    else:
        log("nmap: en marcha...")
        result = run_module(
            nmap_scan.run, target,
            timeout=MODULE_TIMEOUTS["nmap"], label="nmap", on_error=log,
        )
        if result:
            port_findings = result
            findings.extend(result)
            log(f"nmap: hecho — {len(result)} puertos abiertos")
        else:
            log("nmap: sin resultado (fallo o timeout)")

    resolved_targets = web_targets.resolve_from_nmap(target, port_findings, base_path=args.base_path)
    for wt in resolved_targets:
        log(f"target web: {wt.base_url}")

    if "nuclei" in missing_tools:
        log("nuclei: omitido (binario no encontrado)")
    else:
        # nuclei recibe el host a pelo, no un web_target: hace su
        # propia detección de protocolos/puertos (http, https, ssh...)
        # y acotarlo a un solo esquema/puerto le haría perder
        # cobertura (p.ej. las plantillas de SSH que ya ha encontrado
        # en los labs probados).
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

    smb_ldap_ports = ("139/tcp", "445/tcp", "389/tcp", "636/tcp")
    tiene_smb_o_ldap = any(
        f.get("name") == "PORT" and f.get("detail", "").startswith(smb_ldap_ports)
        for f in port_findings
    )
    if not tiene_smb_o_ldap:
        log("enum4linux-ng: omitido (nmap no vio SMB/LDAP abiertos)")
    elif "enum4linux-ng" in missing_tools:
        log("enum4linux-ng: omitido (binario no encontrado)")
    else:
        log("enum4linux-ng: en marcha...")
        result = run_module(
            enum4linux_scan.run, target,
            timeout=MODULE_TIMEOUTS["enum4linux"], label="enum4linux", on_error=log,
        )
        if result:
            findings.extend(result)
            log(f"enum4linux-ng: hecho — {len(result)} hallazgos")
        else:
            log("enum4linux-ng: sin resultado (fallo, timeout, sin sesión SMB/LDAP, o nada que reportar)")

    multiple = len(resolved_targets) > 1
    for wt in resolved_targets:
        findings.extend(_scan_web_target(wt, missing_tools, multiple))

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

    writeup_content = report.render_writeup(target, pistas, contexto)
    if args.polish:
        log("polish: pidiendo a Claude (CLI local) que mejore la redacción del recon...")
        pulido = run_module(
            ai_redact.polish, target, pistas, contexto,
            timeout=MODULE_TIMEOUTS["polish"], label="polish", on_error=log,
        )
        if pulido:
            writeup_content = pulido
            log("polish: hecho")
        else:
            log("polish: no disponible (sin el comando `claude` en PATH, timeout, o error) — se usa la redacción determinista")

    writeup_path = out_dir / "recon_writeup.md"
    with open(writeup_path, "w", encoding="utf-8") as f:
        f.write(writeup_content)
    log(f"recon para writeup: guardado: {writeup_path}")

    print(report.render_terminal(target, pistas, contexto))

    return 0


if __name__ == "__main__":
    sys.exit(main())
