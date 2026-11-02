from dojohack import cli


class TestSameHost:
    def test_same_host_matches(self):
        assert cli._same_host("http://aceituno.thl/wp-login.php", "aceituno.thl") is True

    def test_different_host_is_out_of_scope(self):
        # regresión del leak de alcance: katana seguía enlaces reales a
        # terceros (CDNs, créditos de WordPress, licencias en GitHub)
        # que no deben llegar a dalfox/arjun/las sondas propias.
        assert cli._same_host("https://es.wordpress.org/plugins/", "aceituno.thl") is False
        assert cli._same_host("https://github.com/some/lib", "aceituno.thl") is False

    def test_subdomain_is_not_treated_as_same_host(self):
        assert cli._same_host("http://cdn.aceituno.thl/x.js", "aceituno.thl") is False

    def test_malformed_url_is_out_of_scope_not_an_error(self):
        assert cli._same_host("http://[bad]/path", "aceituno.thl") is False

    def test_url_without_a_resolvable_host_is_out_of_scope(self):
        assert cli._same_host("not a url at all", "aceituno.thl") is False


class TestSkipReason:
    def test_missing_binary_wins_over_being_active(self):
        reason = cli._skip_reason("dalfox", {"dalfox"}, {"dalfox"})
        assert reason == "binario no encontrado"

    def test_disabled_by_skip_or_only(self):
        reason = cli._skip_reason("dalfox", set(), {"wpscan"})
        assert reason == "desactivado por --skip/--only"

    def test_runs_when_installed_and_active(self):
        assert cli._skip_reason("dalfox", set(), {"dalfox"}) is None
