"""
Preprocesado de hallazgos: agrupación de duplicados + detección de
confianza por reglas. Portado del preprocessor.py de PocketHacker
(~/PocketHacker/pocketHacker_debian/preprocessor.py) — mismo
esqueleto y misma idea general (mover la parte mecánica del análisis
a reglas deterministas, sin IA, antes de que el clasificador final
solo tenga que redactar) — pero las reglas de texto se han
reescrito contra lo que producen DE VERDAD los módulos/sondas de
DojoHack, no contra el texto de wstg-scan/PocketHacker.

Diferencia importante de filosofía frente a PocketHacker: las pistas
de las sondas propias (SSTI/SSRF/PATH_TRAVERSAL) ya están redactadas
en la voz dubitativa final de DojoHack — nunca dicen "confirmado" en
el texto, a propósito (ver CLAUDE.md: "las pistas finales nunca
distinguen confirmado vs heurístico en el texto"). Por eso su
confianza NO se infiere del texto (al contrario que en PocketHacker,
donde \\bconfirmad[oa]\\b sí aparecía literalmente porque esas sondas
hablaban en voz de auditoría) — se reconocen por categoría:
CATEGORIAS_SIEMPRE_CONFIRMADAS. Nuestras sondas solo emiten hallazgo
cuando ya verificaron evidencia real (no tienen variante heurística),
así que esto es seguro y además no depende de que la redacción del
texto no cambie con el tiempo.

Para el resto (nmap/nuclei/ffuf/katana/dalfox/trufflehog) sigue
aplicando inferencia por texto, igual que en PocketHacker, porque esos
siguen siendo hallazgos "en bruto" — redactarlos en voz dubitativa
final es el trabajo pendiente del clasificador de pistas (paso 7 de
la hoja de ruta), no de este módulo.

No se porta _categoria_canonica() de PocketHacker: ese problema
(la misma vulnerabilidad apareciendo como string genérico "[VULN] ..."
Y como dict específico, cayendo en grupos distintos) no existe aquí —
todos los módulos de DojoHack emiten siempre dicts con una categoría
("name") concreta y consistente, sin el formato heredado de strings
con prefijo que sí arrastraba PocketHacker.
"""

import re
from collections import defaultdict

# Categorías de nuestras sondas propias: por construcción, solo
# emiten hallazgo cuando ya verificaron evidencia real — su
# confianza es siempre "confirmado", sin necesidad de inferirla de
# un texto que a propósito nunca lo dice.
CATEGORIAS_SIEMPRE_CONFIRMADAS = {"SSTI", "SSRF", "PATH_TRAVERSAL"}

# --- Reglas de ruido: datos sin valor de seguridad real ---
NOISE_PATTERNS = [
    (re.compile(r"AKIAIOSFODNN7EXAMPLE"), "Clave AWS de ejemplo de la documentación, no una credencial real"),
    (re.compile(r"\b(test|example|user|admin|new|foo|bar)@(example\.(com|org)|email\.com|test\.com)\b", re.I), "Email de ejemplo/placeholder, no un dato real"),
    (re.compile(r"\btech-detect\b|\b[\w-]+-detect\b", re.I), "Fingerprinting de tecnología (nuclei), sin implicación de seguridad"),
    (re.compile(r"ssh-server-enumeration|ssh-auth-methods", re.I), "Enumeración informativa de SSH (nuclei), sin implicación directa"),
    (re.compile(r"\bssh-hostkey\b|\bssh2?-enum-algos\b", re.I), "Volcado de fingerprint/algoritmos de SSH (nmap -sC), sin implicación directa"),
]

# --- Reglas de confianza (solo para hallazgos en bruto de módulos de
# terceros, todavía sin pasar por el clasificador de pistas — ver
# CATEGORIAS_SIEMPRE_CONFIRMADAS para las sondas propias) ---
CONFIRMED_PATTERNS = [
    re.compile(r"file:///etc/passwd"),  # SSRF/path traversal: lectura real confirmada
    re.compile(r"root:.*:0:0:"),        # lectura real de /etc/passwd
    re.compile(r"\(tipo V\)", re.I),    # Dalfox tipo V = Verified (ejecución confirmada vía navegador headless)
    re.compile(r"\bconfirmad[oa]\b", re.I),
]
HEURISTIC_PATTERNS = [
    re.compile(r"\bposible\b|\bpuede ser\b|\bpotencial\b|\bpossible\b", re.I),
]
# Dalfox tipo R = Reflected: el payload aparece en la respuesta, pero
# Dalfox mismo no confirma que se ejecute — no es ruido ni heurística
# de texto sin más, es "probable" (requiere verificación manual).
DALFOX_REFLECTED_PATTERN = re.compile(r"\(tipo R\)", re.I)


def _normalize(finding) -> dict:
    """Lleva un hallazgo a una forma común: {categoria, texto,
    severidad}. Los módulos de DojoHack solo producen dicts
    {"name","detail","severity"} — se deja el camino de strings con
    prefijo "[CATEGORIA] ..." por si algún día hace falta (mismo
    convenio que PocketHacker), pero ningún módulo actual lo usa."""
    if isinstance(finding, dict):
        return {
            "categoria": str(finding.get("name", "OTRO")).strip(),
            "texto": str(finding.get("detail", "")).strip(),
            "severidad": (finding.get("severity") or "").lower() or None,
        }
    text = str(finding).strip()
    m = re.match(r"^\[([^\]]+)\]\s*(.*)$", text, re.S)
    if m:
        return {"categoria": m.group(1).strip(), "texto": m.group(2).strip(), "severidad": None}
    return {"categoria": "OTRO", "texto": text, "severidad": None}


def _confidence(texto: str, categoria: str) -> str:
    if categoria in CATEGORIAS_SIEMPRE_CONFIRMADAS:
        return "confirmado"
    blob = f"[{categoria}] {texto}"
    if any(p.search(blob) for p in CONFIRMED_PATTERNS):
        return "confirmado"
    if DALFOX_REFLECTED_PATTERN.search(blob):
        return "probable"
    if any(p.search(blob) for p in HEURISTIC_PATTERNS):
        return "heurístico"
    return "probable"


def _is_noise(texto: str, categoria: str):
    blob = f"[{categoria}] {texto}"
    for pattern, motivo in NOISE_PATTERNS:
        if pattern.search(blob):
            return motivo
    return None


def _group_key(item: dict) -> str:
    """Clave de agrupación: categoría + un resumen del texto que
    ignora la parte variable (URLs, query strings) para que varias
    instancias del mismo hallazgo (ej. el mismo check de nuclei
    repetido en varias rutas) caigan en el mismo grupo."""
    forma = re.sub(r"https?://\S+", "", item["texto"])
    forma = re.sub(r"[?&]\S+", "", forma)
    forma = re.sub(r"\s+", " ", forma).strip().lower()[:60]
    return f"{item['categoria']}|{forma}"


def preprocess_findings(findings: list) -> dict:
    """Devuelve una estructura ya agrupada y con confianza/ruido
    detectados. Formato:
    {
      "grupos": [
        {"categoria", "confianza", "instancias", "evidencia": [textos], "severidad_origen"},
        ...
      ],
      "ruido": [{"detalle", "motivo"}]
    }"""
    normalizados = [_normalize(f) for f in (findings or [])]

    ruido = []
    utiles = []
    for item in normalizados:
        motivo = _is_noise(item["texto"], item["categoria"])
        if motivo:
            ruido.append({"detalle": f"[{item['categoria']}] {item['texto']}"[:200], "motivo": motivo})
        else:
            utiles.append(item)

    grupos_map = defaultdict(lambda: {"evidencia": [], "severidades": set(), "total_instancias": 0})
    for item in utiles:
        key = _group_key(item)
        g = grupos_map[key]
        g["categoria"] = item["categoria"]
        g["total_instancias"] += 1  # cuenta siempre, independientemente del tope de muestras
        if len(g["evidencia"]) < 8:  # muestra acotada de evidencia por grupo
            g["evidencia"].append(item["texto"][:250])
        if item["severidad"]:
            g["severidades"].add(item["severidad"])

    grupos = []
    for g in grupos_map.values():
        confianzas = [_confidence(e, g["categoria"]) for e in g["evidencia"]]
        if "confirmado" in confianzas:
            conf = "confirmado"
        elif "heurístico" in confianzas and "probable" not in confianzas:
            conf = "heurístico"
        else:
            conf = "probable"
        grupos.append({
            "categoria": g["categoria"],
            "confianza": conf,
            "instancias": g["total_instancias"],
            "evidencia": g["evidencia"],
            "severidad_origen": sorted(g["severidades"]) or None,
        })

    # Orden: primero por si trae severidad de origen crítica, luego por instancias
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def _rank(gr):
        sevs = gr["severidad_origen"] or []
        best = min((sev_rank.get(s, 5) for s in sevs), default=5)
        return (best, -gr["instancias"])

    grupos.sort(key=_rank)

    return {"grupos": grupos, "ruido": ruido}
