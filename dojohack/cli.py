"""
DojoHack — asistente de pistas para practicar CTF.

Uso:
    dojohack <target> [--base-path /subdir] [--name nombre] [--polish]
    dojohack <target> --quick   (diagnóstico rápido de vhost/CMS antes
                                  del pipeline completo — ver quick_scan.py)
    dojohack <target> --skip dalfox,wpscan   (pasada rápida, sin los
                                  módulos caros)
    dojohack <target> --only dalfox          (relanza solo ese módulo
                                  más tarde; se SUMA al findings.json
                                  que ya hubiera en vez de sobrescribir)
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Módulos que --skip/--only pueden controlar -- deliberadamente no
# incluye el fontanería siempre-encendida (vhost_check, route_patterns,
# preprocessor, classifier, report): esos son baratos y alimentan a
# los demás, no tiene sentido desactivarlos por separado.
ALL_MODULES = {
    "nmap", "nuclei", "enum4linux", "vhost_fuzz", "php_cve_check",
    "testssl", "ffuf", "katana", "trufflehog", "wpscan", "dalfox",
    "arjun", "ssti", "ssrf", "path_traversal", "sqli", "command_injection",
}

from . import ai_redact, classifier, php_cve_check, preflight, preprocessor, quick_scan, report, route_patterns, vhost_check, vhost_fuzz, web_targets
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
from .timeouts import MODULE_TIMEOUTS, run_module, run_threadsafe


def log(msg: str) -> None:
    print(f"[dojohack] {msg}", flush=True)


def _skip_reason(name: str, missing_tools: set, active_modules: set) -> str | None:
    """Motivo por el que un módulo no se lanza, o None si debe
    lanzarse — dos motivos posibles: el binario no está instalado
    (missing_tools, de preflight) o se ha desactivado explícitamente
    con --skip/--only (active_modules). Mismo hueco en el que antes
    solo se comprobaba missing_tools."""
    if name in missing_tools:
        return "binario no encontrado"
    if name not in active_modules:
        return "desactivado por --skip/--only"
    return None


def _scan_web_target(wt, missing_tools: set, multiple: bool, active_modules: set) -> list[dict]:
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
        _reason = _skip_reason("vhost_fuzz", missing_tools, active_modules) or (
            "binario ffuf no encontrado" if "ffuf" in missing_tools else None
        )
        if _reason:
            wlog(f"vhost_fuzz: omitido ({_reason})")
        else:
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

    # Módulos independientes entre sí: ninguno necesita el resultado
    # de otro, solo wt — se lanzan todos a la vez en vez de uno
    # detrás de otro. Antes, tres de estos atascándose en su propio
    # timeout (ffuf + dalfox + wpscan a 600s cada uno) sumaban 30
    # minutos solo de esperas, contra un target con contenido real de
    # verdad (ver conversación con Paco, 2026-10-25/26). En paralelo,
    # el peor caso es el del más lento de los seis, no la suma de
    # todos. Usan timeouts.run_threadsafe, no run_module: signal.
    # SIGALRM solo funciona en el hilo principal, así que estos
    # módulos reciben su propio `timeout` y lo propagan hasta
    # subprocess_utils.run()/httpx (ver timeouts.py).
    stage1: dict = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {}

        _reason = _skip_reason("php_cve_check", missing_tools, active_modules)
        if _reason:
            wlog(f"php2shell: omitido ({_reason})")
        else:
            futures[pool.submit(
                run_threadsafe, php_cve_check.check, wt,
                timeout=MODULE_TIMEOUTS["php_cve_check"], label="php_cve_check", on_error=wlog,
            )] = "php_cve_check"

        if wt.scheme != "https":
            wlog("testssl: omitido (no es https)")
        else:
            _reason = _skip_reason("testssl", missing_tools, active_modules)
            if _reason:
                wlog(f"testssl: omitido ({_reason})")
            else:
                wlog("testssl: en marcha...")
                futures[pool.submit(
                    run_threadsafe, testssl_scan.run, wt,
                    timeout=MODULE_TIMEOUTS["testssl"], label="testssl", on_error=wlog,
                )] = "testssl"

        _reason = _skip_reason("ffuf", missing_tools, active_modules)
        if _reason:
            wlog(f"ffuf: omitido ({_reason})")
        else:
            wlog("ffuf: en marcha...")
            futures[pool.submit(
                run_threadsafe, ffuf_scan.fuzz, wt,
                timeout=MODULE_TIMEOUTS["ffuf"], label="ffuf", on_error=wlog,
            )] = "ffuf"

        _reason = _skip_reason("katana", missing_tools, active_modules)
        if _reason:
            wlog(f"katana: omitido ({_reason})")
        else:
            wlog("katana: en marcha...")
            futures[pool.submit(
                run_threadsafe, katana_scan.crawl, wt,
                timeout=MODULE_TIMEOUTS["katana"], label="katana", on_error=wlog,
            )] = "katana"

        _reason = _skip_reason("trufflehog", missing_tools, active_modules)
        if _reason:
            wlog(f"trufflehog: omitido ({_reason})")
        else:
            wlog("trufflehog: en marcha...")
            futures[pool.submit(
                run_threadsafe, trufflehog_scan.run, wt,
                timeout=MODULE_TIMEOUTS["trufflehog"], label="trufflehog", on_error=wlog,
            )] = "trufflehog"

        _reason = _skip_reason("wpscan", missing_tools, active_modules)
        if _reason:
            wlog(f"wpscan: omitido ({_reason})")
        else:
            wlog("wpscan: en marcha...")
            futures[pool.submit(
                run_threadsafe, wpscan_scan.run, wt,
                timeout=MODULE_TIMEOUTS["wpscan"], label="wpscan", on_error=wlog,
            )] = "wpscan"

        for future in as_completed(futures):
            stage1[futures[future]] = future.result()

    result = stage1.get("php_cve_check")
    if result:
        findings.extend(result)
        wlog(f"php2shell: {result[0]['detail']}")
    else:
        wlog("php2shell: sin resultado (fallo, timeout, o no se detecta PHP)")

    result = stage1.get("testssl")
    if result:
        findings.extend(result)
        wlog(f"testssl: hecho — {len(result)} hallazgos")
    elif "testssl" in stage1:
        wlog("testssl: sin resultado (fallo, timeout, o nada que reportar)")

    ffuf_urls: list = []
    ffuf_results = stage1.get("ffuf")
    if ffuf_results:
        result = ffuf_scan.parse_findings(ffuf_results)
        ffuf_urls = ffuf_scan.parse_urls(ffuf_results)
        findings.extend(result)
        wlog(f"ffuf: hecho — {len(result)} rutas encontradas")
    elif "ffuf" in stage1:
        wlog("ffuf: sin resultado (fallo, timeout o nada que reportar)")

    katana_urls: list = []
    katana_forms: list = []
    raw = stage1.get("katana")
    if raw:
        result = katana_scan.parse_findings(raw)
        katana_urls = katana_scan.parse_endpoints(raw)
        katana_forms = katana_scan.parse_forms(raw)
        findings.extend(result)
        wlog(f"katana: hecho — {len(result)} endpoints encontrados")
    elif "katana" in stage1:
        wlog("katana: sin resultado (fallo, timeout o nada que reportar)")

    result = stage1.get("trufflehog")
    if result:
        findings.extend(result)
        wlog(f"trufflehog: hecho — {len(result)} secretos encontrados")
    elif "trufflehog" in stage1:
        wlog("trufflehog: sin resultado (fallo, timeout, no expone .git, o nada que reportar)")

    result = stage1.get("wpscan")
    if result:
        findings.extend(result)
        wlog(f"wpscan: hecho — {len(result)} hallazgos")
    elif "wpscan" in stage1:
        wlog("wpscan: sin resultado (fallo, timeout, no es WordPress, o nada que reportar)")

    rutas_descubiertas = ffuf_urls + katana_urls
    result = route_patterns.scan_paths(rutas_descubiertas)
    if result:
        findings.extend(result)
    wlog(f"patrones de ruta: {len(result)} rutas sospechosas de {len(rutas_descubiertas)} analizadas")

    # dalfox y arjun tampoco dependen entre sí (ambos solo necesitan
    # katana_urls, ya calculado arriba) -- mismo motivo que el bloque
    # de módulos independientes de más arriba para lanzarlos a la vez
    # en vez de uno tras otro.
    stage2: dict = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {}

        _reason = _skip_reason("dalfox", missing_tools, active_modules)
        if _reason:
            wlog(f"dalfox: omitido ({_reason})")
        else:
            wlog("dalfox: en marcha...")
            futures[pool.submit(
                run_threadsafe, dalfox_scan.run, wt, urls=katana_urls or None,
                timeout=MODULE_TIMEOUTS["dalfox"], label="dalfox", on_error=wlog,
            )] = "dalfox"

        _reason = _skip_reason("arjun", missing_tools, active_modules)
        if _reason:
            wlog(f"arjun: omitido ({_reason})")
        elif not katana_urls:
            wlog("arjun: omitido (katana no encontró endpoints que probar)")
        else:
            wlog(f"arjun: en marcha... ({len(katana_urls)} endpoints a comprobar)")
            futures[pool.submit(
                run_threadsafe, arjun_scan.discover, katana_urls,
                timeout=MODULE_TIMEOUTS["arjun"], label="arjun", on_error=wlog,
            )] = "arjun"

        for future in as_completed(futures):
            stage2[futures[future]] = future.result()

    result = stage2.get("dalfox")
    if result:
        findings.extend(result)
        wlog(f"dalfox: hecho — {len(result)} XSS encontrados")
    elif "dalfox" in stage2:
        wlog("dalfox: sin resultado (fallo, timeout o nada que reportar)")

    arjun_points: list = []
    descubiertos = stage2.get("arjun")
    if descubiertos:
        findings.extend(arjun_scan.parse_findings(descubiertos))
        arjun_points = arjun_scan.parse_injection_points(descubiertos)
        wlog(f"arjun: hecho — {sum(len(p) for p in descubiertos.values())} parámetros ocultos en {len(descubiertos)} endpoint(s)")
    elif "arjun" in stage2:
        wlog("arjun: sin resultado (fallo, timeout, o ningún parámetro oculto)")

    injection_points = probe_common.from_urls(katana_urls) + probe_common.from_forms(katana_forms) + arjun_points

    _reason = _skip_reason("ssti", missing_tools, active_modules)
    if _reason:
        wlog(f"ssti: omitido ({_reason})")
    else:
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

    _reason = _skip_reason("ssrf", missing_tools, active_modules)
    if _reason:
        wlog(f"ssrf: omitido ({_reason})")
    else:
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

    _reason = _skip_reason("path_traversal", missing_tools, active_modules)
    if _reason:
        wlog(f"path_traversal: omitido ({_reason})")
    else:
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

    _reason = _skip_reason("sqli", missing_tools, active_modules)
    if _reason:
        wlog(f"sqli: omitido ({_reason})")
    else:
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

    _reason = _skip_reason("command_injection", missing_tools, active_modules)
    if _reason:
        wlog(f"command_injection: omitido ({_reason})")
    else:
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
    parser.add_argument(
        "--quick", action="store_true",
        help=(
            "Diagnóstico rápido (segundos, no minutos) y sale: ¿hay vhost "
            "por nombre? ¿hay un CMS en subdirectorio? Sin nmap ni "
            "fuzzing con wordlist — para saber los parámetros correctos "
            "ANTES de lanzar el pipeline completo, en vez de relanzarlo "
            "2-3 veces. No lanza el resto del pipeline ni toca /etc/hosts."
        ),
    )
    modulos_grupo = parser.add_mutually_exclusive_group()
    modulos_grupo.add_argument(
        "--skip", default=None, metavar="MOD1,MOD2",
        help=(
            "No lanzar estos módulos (lista separada por comas, ej. "
            "--skip dalfox,wpscan). Módulos válidos: " + ", ".join(sorted(ALL_MODULES)) + ". "
            "Si ya hay un findings.json previo en la carpeta de salida, "
            "los hallazgos de este lanzamiento se SUMAN a los que ya "
            "había, en vez de sobrescribirlos — pensado para una pasada "
            "rápida primero y completar con los módulos caros después."
        ),
    )
    modulos_grupo.add_argument(
        "--only", default=None, metavar="MOD1,MOD2",
        help=(
            "Lanzar ÚNICAMENTE estos módulos (lista separada por comas, "
            "ej. --only dalfox). Mismos módulos válidos que --skip, y "
            "mismo comportamiento de sumar en vez de sobrescribir si ya "
            "hay un findings.json previo."
        ),
    )
    args = parser.parse_args()

    if args.skip or args.only:
        nombres = {n.strip() for n in (args.skip or args.only).split(",") if n.strip()}
        desconocidos = nombres - ALL_MODULES
        if desconocidos:
            parser.error(
                f"módulo(s) no reconocido(s): {', '.join(sorted(desconocidos))}. "
                f"Válidos: {', '.join(sorted(ALL_MODULES))}"
            )
        active_modules = (ALL_MODULES - nombres) if args.skip else nombres
    else:
        active_modules = set(ALL_MODULES)

    if args.quick:
        quick_scan.run(args.target)
        return 0

    target = args.target
    out_dir = Path(args.output) if args.output else _PROJECT_ROOT / "output" / (args.name or target)
    out_dir.mkdir(parents=True, exist_ok=True)

    findings: list = []

    log(f"objetivo: {target}")

    missing_tools = preflight.check_and_install()

    port_findings: list = []
    _reason = _skip_reason("nmap", missing_tools, active_modules)
    if _reason:
        log(f"nmap: omitido ({_reason})")
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

    _reason = _skip_reason("nuclei", missing_tools, active_modules)
    if _reason:
        log(f"nuclei: omitido ({_reason})")
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
    elif "enum4linux" not in active_modules:
        log("enum4linux-ng: omitido (desactivado por --skip/--only)")
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
        findings.extend(_scan_web_target(wt, missing_tools, multiple, active_modules))

    out_path = out_dir / "findings.json"
    if (args.skip or args.only) and out_path.is_file():
        # --skip/--only es para completar una pasada anterior, no para
        # sustituirla -- sin esto, "dojohack <target> --only dalfox"
        # borraría todo lo que ya tenías de ffuf/wpscan/etc. de la
        # pasada rápida de antes (ver conversación con Paco, 2026-10-26).
        try:
            previos = json.loads(out_path.read_text(encoding="utf-8")).get("findings", [])
        except (OSError, json.JSONDecodeError):
            previos = []
        if previos:
            log(f"combinando con {len(previos)} hallazgos ya existentes en {out_path}")
            findings = previos + findings

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
