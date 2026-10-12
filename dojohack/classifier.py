"""
Clasificador de pistas — redacción dubitativa uniforme. Último paso
antes del informe final (paso 8, pendiente): toma la estructura ya
agrupada/con confianza calculada por preprocessor.preprocess_findings()
y la convierte en pistas, todas con el mismo tono dubitativo —el texto
nunca distingue "confirmado" de "heurístico" (eso se usó puertas
adentro, en preprocessor, solo para decidir agrupación/ruido, no se
repite en la redacción final — ver CLAUDE.md).

Mismo esqueleto que rule_classifier.py de PocketHacker
(~/PocketHacker/pocketHacker_debian/rule_classifier.py): una función
redactora por categoría, probada en orden de prioridad dentro de cada
una, con un fallback genérico que nunca descarta un grupo en
silencio. La redacción es otra: apunta a la técnica a explorar, nunca
"confirma" nada ni da el payload de explotación completo.

Categorías que NO se convierten en pista (van a "contexto": recon
puro, sin ninguna técnica que sugerir por sí mismas) — PORT, FFUF,
KATANA. Lo que sí merece ser pista dentro de FFUF/KATANA ya salió
como su propia categoría (RUTA_SOSPECHOSA, ver route_patterns.py);
repetir cada URL/puerto crudo como "pista" solo sería ruido.

Categorías que ya redactan su propia pista final dubitativa al
generarse (las sondas propias y la tabla de patrones de ruta) pasan
casi sin tocar — solo se homogeneiza el formato de salida.
"""

import re

CATEGORIAS_CONTEXTO = {"PORT", "FFUF", "KATANA"}

CATEGORIAS_YA_REDACTADAS = {"SSTI", "SSRF", "PATH_TRAVERSAL", "SQLI", "COMMAND_INJECTION", "RUTA_SOSPECHOSA", "VHOST_FUZZ"}


def _redact_nuclei(grupo: dict) -> str:
    texto = grupo["evidencia"][0]
    severidad = (grupo["severidad_origen"] or ["info"])[0]

    if re.search(r"missing.?security.?headers", texto, re.I):
        return (
            "nuclei señaló que faltan cabeceras de seguridad HTTP habituales. "
            "Por sí solo no es gran cosa, pero según qué más haya en el sitio "
            "podría abrir la puerta a otras técnicas (XSS, clickjacking...)."
        )
    if re.search(r"old-copyright", texto, re.I):
        return (
            "nuclei encontró una fecha de copyright antigua en alguna página. "
            "Suele ser solo una señal de que el contenido lleva tiempo sin "
            "tocarse — podría valer la pena mirar si el resto del sitio "
            "también está desactualizado."
        )
    if re.search(r"options.?method", texto, re.I):
        return (
            "el servidor responde al método OPTIONS revelando qué métodos "
            "soporta. Poca cosa por sí sola, pero es un dato más de "
            "reconocimiento que puede encajar con otra pista."
        )

    if severidad in ("critical", "high"):
        return (
            f"nuclei marcó algo de severidad {severidad} por aquí — sin "
            f"confirmarlo del todo, pero pinta a que vale la pena pararse a "
            f"mirarlo con calma: {texto[:200]}"
        )
    if severidad == "medium":
        return f"nuclei encontró algo que podría ser relevante: {texto[:200]}. No está de más revisarlo."
    return (
        f"nuclei dejó esta nota de reconocimiento: {texto[:200]}. Probablemente "
        f"no sea gran cosa por sí sola, pero puede dar contexto para otra pista."
    )


def _redact_dalfox(grupo: dict) -> str:
    texto = grupo["evidencia"][0]
    if re.search(r"\(tipo V\)", texto, re.I):
        return (
            f"dalfox probó un payload de XSS y la cosa pinta bien — algo en "
            f"la respuesta sugiere que sí que se llega a ejecutar. "
            f"Detalle: {texto[:200]}"
        )
    return (
        f"dalfox vio que un payload de XSS se refleja en la respuesta, pero "
        f"sin confirmar que de verdad se ejecute — habría que probarlo a "
        f"mano para estar seguro. Detalle: {texto[:200]}"
    )


def _redact_trufflehog(grupo: dict) -> str:
    texto = grupo["evidencia"][0]
    return (
        f"por ahí anda lo que parece un secreto filtrado (token, clave, "
        f"credencial...) en un repositorio expuesto. Podría ser real y "
        f"seguir activo, o puede que ya esté revocado — solo se sabe "
        f"probándolo. Detalle: {texto[:200]}"
    )


def _redact_nmap_script(grupo: dict) -> str:
    texto = grupo["evidencia"][0]

    if re.search(r"\bftp-anon\b", texto, re.I):
        return (
            f"nmap dice que el FTP permite login anónimo: {texto}. Si hay "
            f"algo interesante en ese FTP, se podría leer (o incluso escribir, "
            f"según permisos) sin credenciales."
        )
    if re.search(r"\bssl-cert\b", texto, re.I):
        return (
            f"nmap leyó el certificado TLS: {texto}. El nombre que trae "
            f"(Common Name / Subject Alternative Name) puede ser el hostname "
            f"real de la app, distinto del que se usó para escanear — vale la "
            f"pena probarlo si hay vhosting por nombre de por medio."
        )
    if re.search(r"\bsmb-?(os-discovery|security-mode|protocols)\b", texto, re.I):
        return f"nmap sacó esto de SMB: {texto}. Dato de reconocimiento, por si da pie a enumerar más o a alguna técnica específica de SMB."
    return f"nmap dejó esta nota de un script: {texto[:250]}. Puede que no sea gran cosa por sí sola, pero es otra pieza de reconocimiento."


def _redact_wpscan(grupo: dict) -> str:
    texto = grupo["evidencia"][0]

    if re.search(r"^WordPress \d", texto):
        if "insecure" in texto or "estado: insecure" in texto:
            return (
                f"wpscan dice que el WordPress de esta instalación está "
                f"desactualizado (versión conocida como insegura): {texto}. "
                f"Podría tener parches de seguridad pendientes — valdría la "
                f"pena mirar si hay algo público para esa versión."
            )
        return f"wpscan confirmó la versión de WordPress instalada: {texto}. Dato de reconocimiento."

    if re.search(r"^plugin '", texto):
        extra = " — y encima desactualizado" if "desactualizado" in texto else ""
        return (
            f"wpscan encontró un plugin instalado{extra}: {texto}. Sin un "
            f"token de la API de wpscan no se puede saber aquí si tiene "
            f"vulnerabilidades conocidas, pero es otra pieza de software de "
            f"terceros expuesta — vale la pena mirarla a mano."
        )

    if re.search(r"^tema activo:", texto):
        return f"wpscan identificó el tema activo de WordPress: {texto}. Dato de reconocimiento, por si hay algo público para ese tema/versión."

    m = re.match(r"^usuario encontrado:\s*(.+)$", texto)
    if m:
        return (
            f"wpscan encontró un usuario: {m.group(1)} — un nombre de "
            f"usuario válido es justo lo que hace falta para intentar "
            f"fuerza bruta o probar credenciales por defecto en /wp-login.php."
        )

    if re.search(r"xml-?rpc", texto, re.I):
        return (
            f"wpscan señala que xmlrpc.php está habilitado: {texto}. Suele "
            f"servir para fuerza bruta más eficiente (multicall) o, según la "
            f"configuración, otras técnicas vía pingback."
        )

    if re.search(r"listado de directorio|directory listing", texto, re.I):
        return f"wpscan encontró un listado de directorio activado: {texto}. Puede dejar ver ficheros que no deberían ser públicos."

    return f"wpscan dejó esta nota de reconocimiento sobre el WordPress: {texto[:200]}."


_REDACTORES = {
    "NUCLEI": _redact_nuclei,
    "DALFOX": _redact_dalfox,
    "TRUFFLEHOG": _redact_trufflehog,
    "WPSCAN": _redact_wpscan,
    "NMAP_SCRIPT": _redact_nmap_script,
}


def _redact_fallback(grupo: dict) -> str:
    texto = grupo["evidencia"][0]
    return f"Hallazgo sin plantilla específica todavía — revisa la evidencia a mano: {texto[:200]}"


def classify(preprocesado: dict) -> list[dict]:
    """Devuelve la lista final de pistas a partir de la salida de
    preprocessor.preprocess_findings(). Cada pista:
    {"categoria", "texto", "instancias"}. Nunca distingue "confirmado"
    de "heurístico" en el texto — todas igual de dubitativas."""
    pistas = []
    for grupo in preprocesado["grupos"]:
        categoria = grupo["categoria"]
        if categoria in CATEGORIAS_CONTEXTO:
            continue

        if categoria in CATEGORIAS_YA_REDACTADAS:
            texto = grupo["evidencia"][0]
        else:
            redactor = _REDACTORES.get(categoria, _redact_fallback)
            texto = redactor(grupo)

        if grupo["instancias"] > 1:
            texto += f" (visto {grupo['instancias']} veces)"

        pistas.append({
            "categoria": categoria,
            "texto": texto,
            "instancias": grupo["instancias"],
        })
    return pistas


def extract_context(preprocesado: dict) -> list[str]:
    """Devuelve líneas de contexto puro (puertos, recuento de rutas
    rastreadas...) que no son pistas en sí mismas, pero que el
    informe final sí debe mostrar para que Paco tenga el panorama
    completo de la superficie analizada."""
    contexto = []
    for grupo in preprocesado["grupos"]:
        if grupo["categoria"] not in CATEGORIAS_CONTEXTO:
            continue
        for e in grupo["evidencia"]:
            contexto.append(f"[{grupo['categoria']}] {e}")
    return contexto
