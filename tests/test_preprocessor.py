from dojohack.preprocessor import preprocess_findings


def test_groups_duplicate_findings_and_counts_all_instances():
    findings = [
        {"name": "NUCLEI", "detail": "possible XSS at http://x/a?id=1", "severity": "medium"},
        {"name": "NUCLEI", "detail": "possible XSS at http://x/b?id=2", "severity": "medium"},
    ]
    result = preprocess_findings(findings)

    assert len(result["grupos"]) == 1
    assert result["grupos"][0]["instancias"] == 2


def test_own_probe_categories_are_always_confirmed_even_without_text_markers():
    # Las sondas propias (SSTI/SSRF/SQLI/COMMAND_INJECTION/PATH_TRAVERSAL)
    # redactan en voz dubitativa a propósito -- la confianza se decide
    # por categoría, no buscando "confirmado" en el texto.
    findings = [{"name": "SSTI", "detail": "por aquí hay algo, podría ser esto", "severity": "high"}]
    result = preprocess_findings(findings)

    assert result["grupos"][0]["confianza"] == "confirmado"


def test_dalfox_verified_is_confirmed_and_reflected_is_probable():
    findings = [
        {"name": "DALFOX", "detail": "GET param 'q' (tipo V) — payload: <script>", "severity": "high"},
        {"name": "DALFOX", "detail": "GET param 'r' (tipo R) — payload: <script>", "severity": "medium"},
    ]
    result = preprocess_findings(findings)

    confianza_por_texto = {g["evidencia"][0]: g["confianza"] for g in result["grupos"]}
    assert confianza_por_texto["GET param 'q' (tipo V) — payload: <script>"] == "confirmado"
    assert confianza_por_texto["GET param 'r' (tipo R) — payload: <script>"] == "probable"


def test_example_credentials_are_filtered_as_noise_not_as_findings():
    findings = [
        {"name": "TRUFFLEHOG", "detail": "found AKIAIOSFODNN7EXAMPLE in docs/example.md", "severity": "high"},
        {"name": "WPSCAN", "detail": "contact admin@example.com found in page footer", "severity": "low"},
    ]
    result = preprocess_findings(findings)

    assert result["grupos"] == []
    assert len(result["ruido"]) == 2


def test_critical_severity_groups_sort_before_info_ones():
    findings = [
        {"name": "NUCLEI", "detail": "info disclosure", "severity": "info"},
        {"name": "NUCLEI", "detail": "RCE confirmado de verdad", "severity": "critical"},
    ]
    result = preprocess_findings(findings)

    assert result["grupos"][0]["severidad_origen"] == ["critical"]
