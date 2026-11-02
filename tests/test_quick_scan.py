from dojohack import quick_scan


def test_skips_subdir_probing_when_wordpress_already_reveals_the_real_hostname(monkeypatch, capsys):
    # Regresión: cuando la raíz ya delata el hostname real vía
    # wp-json, sondear subdirectorios solo da ruido (ej. un /admin de
    # otra cosa) y acaba sugiriendo un --base-path contradictorio.
    monkeypatch.setattr(quick_scan, "_try_schemes", lambda target: ("http://192.168.72.136", None))
    monkeypatch.setattr(
        quick_scan.vhost_check, "probe",
        lambda base_url: {"default_page_signals": [], "wp_hostname": "aceituno.thl"},
    )
    monkeypatch.setattr(quick_scan.vhost_check, "is_ip", lambda h: h == "192.168.72.136")

    llamadas = []
    monkeypatch.setattr(
        quick_scan, "_probe_subdirs",
        lambda base_url: llamadas.append(base_url) or [("admin", 302)],
    )

    quick_scan.run("192.168.72.136")

    assert llamadas == []
    salida = capsys.readouterr().out
    assert "aceituno.thl" in salida
    assert "--base-path" not in salida


def test_probes_subdirs_when_no_wordpress_hostname_is_found(monkeypatch, capsys):
    monkeypatch.setattr(quick_scan, "_try_schemes", lambda target: ("http://192.168.72.134", None))
    monkeypatch.setattr(
        quick_scan.vhost_check, "probe",
        lambda base_url: {"default_page_signals": [], "wp_hostname": None},
    )
    monkeypatch.setattr(quick_scan.vhost_check, "is_ip", lambda h: h == "192.168.72.134")
    monkeypatch.setattr(quick_scan, "_probe_subdirs", lambda base_url: [("wordpress", 301)])

    quick_scan.run("192.168.72.134")

    salida = capsys.readouterr().out
    assert "--base-path /wordpress" in salida


def test_does_nothing_when_the_target_does_not_respond(monkeypatch, capsys):
    monkeypatch.setattr(quick_scan, "_try_schemes", lambda target: None)

    quick_scan.run("192.168.72.200")

    salida = capsys.readouterr().out
    assert "nada que diagnosticar" in salida
