from dojohack.vhost_check import _find_wordpress_hostname, is_ip


def test_is_ip_true_for_ipv4():
    assert is_ip("192.168.72.129") is True


def test_is_ip_false_for_hostname():
    assert is_ip("aceituno.thl") is False


def test_finds_hostname_from_the_link_header():
    # visto de primera mano contra aceituno.thl: WordPress manda esta
    # cabecera con SU hostname configurado, sin importar por qué
    # nombre/IP se le pida la página.
    headers = {"Link": '<http://aceituno.thl/wp-json/>; rel="https://api.w.org/"'}
    assert _find_wordpress_hostname(headers, "") == "aceituno.thl"


def test_finds_hostname_from_the_body_when_there_is_no_link_header():
    body = '<link rel="https://api.w.org/" href="http://aceituno.thl/wp-json/" />'
    assert _find_wordpress_hostname({}, body) == "aceituno.thl"


def test_returns_none_when_nothing_mentions_wp_json():
    assert _find_wordpress_hostname({}, "<html>nada por aquí</html>") is None


def test_headers_can_be_none():
    assert _find_wordpress_hostname(None, "sin wp-json en ningún lado") is None
