import signal
import subprocess
import time

import pytest

from dojohack.timeouts import run_module, run_threadsafe


# --- run_module: usado por los módulos que corren en el hilo
# principal (ver cli.py) ---

def test_run_module_returns_the_result_on_success():
    assert run_module(lambda x: x * 2, 3, timeout=5, label="doblar") == 6


def test_run_module_swallows_exceptions_and_reports_via_on_error():
    def falla():
        raise RuntimeError("boom")

    errores = []
    result = run_module(falla, timeout=5, label="falla", on_error=errores.append)

    assert result is None
    assert len(errores) == 1
    assert "boom" in errores[0]


def test_run_module_does_not_require_on_error():
    def falla():
        raise RuntimeError("boom")

    assert run_module(falla, timeout=5, label="falla") is None


@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="signal.SIGALRM solo existe en Unix")
def test_run_module_enforces_a_real_timeout_on_unix():
    errores = []
    result = run_module(lambda: time.sleep(2), timeout=1, label="lento", on_error=errores.append)

    assert result is None
    assert "tope de 1s" in errores[0]


# --- run_threadsafe: usado por los módulos lanzados en paralelo vía
# ThreadPoolExecutor (ver cli.py, stage1/stage2) -- sin signal.SIGALRM,
# así que debe funcionar igual en Windows que en la VM Kali. ---

def test_run_threadsafe_returns_the_result_on_success():
    assert run_threadsafe(lambda *, timeout: timeout * 2, timeout=5, label="doblar") == 10


def test_run_threadsafe_catches_timeout_expired_without_signals():
    def func(*, timeout):
        raise subprocess.TimeoutExpired(cmd="dalfox", timeout=timeout)

    errores = []
    result = run_threadsafe(func, timeout=373, label="dalfox", on_error=errores.append)

    assert result is None
    assert "373s" in errores[0]


def test_run_threadsafe_catches_generic_exceptions():
    def func(*, timeout):
        raise RuntimeError("boom")

    errores = []
    result = run_threadsafe(func, timeout=5, label="arjun", on_error=errores.append)

    assert result is None
    assert "boom" in errores[0]


def test_run_threadsafe_propagates_timeout_kwarg_to_func():
    recibido = {}

    def func(*, timeout):
        recibido["timeout"] = timeout
        return "ok"

    run_threadsafe(func, timeout=45, label="arjun")
    assert recibido["timeout"] == 45
