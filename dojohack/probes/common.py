"""
Utilidades compartidas entre las sondas propias de inyección (SSTI, y
lo que venga después: SSRF, XSS, path traversal...). Construyen los
"puntos de inyección" — GET con parámetros de query string, POST con
campos de formulario — a partir de lo que ya rastreó katana, para que
cada sonda no tenga que repetir esta lógica.
"""

from urllib.parse import parse_qs, urlparse


def from_urls(urls: list[str]) -> list[dict]:
    """Un punto de inyección GET por cada parámetro de query string
    en las URLs dadas (normalmente las que rastreó katana).
    {"method", "url" (sin query string), "param", "params" (todos los
    parámetros originales, para no romper la petición al cambiar
    solo uno)}."""
    points = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        base_url = url.split("?", 1)[0]
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        for param in params:
            points.append({
                "method": "GET", "url": base_url,
                "param": param, "params": dict(params),
            })
    return points


def from_forms(forms: list[dict]) -> list[dict]:
    """Un punto de inyección POST por cada campo de un formulario
    (normalmente los que rastreó katana con -fx). Los demás campos
    del mismo formulario se rellenan con un valor inocuo, para que no
    falle por validación de 'required' en el campo que no se está
    probando."""
    points = []
    for form in forms:
        if form.get("method", "GET").upper() != "POST":
            continue
        fields = form.get("parameters", [])
        for param in fields:
            points.append({
                "method": "POST", "url": form["action"],
                "param": param,
                "params": {p: "test" for p in fields},
            })
    return points
