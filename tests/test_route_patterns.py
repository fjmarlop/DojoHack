from dojohack import route_patterns


def test_wordpress_author_page_extracts_leaked_username():
    findings = route_patterns.scan_paths(["http://aceituno.thl/author/dylan/"])
    assert len(findings) == 1
    assert findings[0]["name"] == "RUTA_SOSPECHOSA"
    assert "dylan" in findings[0]["detail"]


def test_matching_patterns_on_the_same_path_combine_into_one_finding():
    # wp-login.php coincide con el patrón genérico de login Y con el
    # específico de WordPress -- debe quedar una sola pista con ambas
    # técnicas, no dos hallazgos separados.
    findings = route_patterns.scan_paths(["http://aceituno.thl/wp-login.php"])
    assert len(findings) == 1
    detail = findings[0]["detail"]
    assert "fuerza bruta" in detail
    assert "WordPress" in detail


def test_unmatched_path_produces_no_finding():
    findings = route_patterns.scan_paths(["http://aceituno.thl/about-us"])
    assert findings == []


def test_duplicate_paths_are_only_scanned_once():
    findings = route_patterns.scan_paths(
        ["http://x/login.php", "http://x/login.php"]
    )
    assert len(findings) == 1


def test_exposed_git_directory_suggests_cloning_the_history():
    findings = route_patterns.scan_paths(["http://x/.git/config"])
    assert len(findings) == 1
    assert "historial" in findings[0]["detail"]
