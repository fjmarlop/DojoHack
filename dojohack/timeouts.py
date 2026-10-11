"""
Timeout por módulo — mismo patrón que PocketHacker (runner.py), pero
generalizado: en vez de envolver w.safe_execute() de wstg-scan, envuelve
cualquier función normal. Cada módulo del pipeline tiene su propio tope
de tiempo, así uno que se cuelgue no se lleva el escaneo entero — se
registra el error y se sigue con el siguiente.

MODULE_TIMEOUTS se amplía módulo a módulo según se van sumando al
pipeline (hoy solo nmap).

LIMITACIÓN CONOCIDA: signal.SIGALRM solo existe en Unix. Pensado para
correr en la VM Kali del lab de CTF, no en Windows — si algún día se
ejecuta en Windows (p.ej. para iterar rápido sin la VM), el timeout
queda desactivado y un módulo colgado no tiene ningún tope. Se avisa
una vez al importar el módulo, no en cada llamada, para no ensuciar el
log del pipeline.
"""

import signal
import sys
from contextlib import contextmanager

MODULE_TIMEOUTS = {
    "nmap": 300,
    "nuclei": 600,
    "ffuf": 600,
    "katana": 300,
    "dalfox": 600,
    "trufflehog": 300,
    "ssti": 300,
}

_HAS_ALARM = hasattr(signal, "SIGALRM")
if not _HAS_ALARM:
    print(
        "[dojohack] aviso: timeouts por módulo desactivados (no hay signal.SIGALRM "
        "en este sistema — normal en Windows, pensado para correr en la VM Kali).",
        file=sys.stderr,
    )


class ModuleTimeoutError(BaseException):
    """Hereda de BaseException, no de Exception — igual que en
    PocketHacker (runner.py) y por el mismo motivo: si un módulo
    envuelve sus propios sub-pasos en un try/except Exception genérico,
    ModuleTimeoutError no debe quedar atrapada ahí como si fuera un
    fallo normal de ese sub-paso — tiene que abortar el módulo entero,
    no solo el sub-paso en el que estaba en ese instante."""


@contextmanager
def _module_alarm(seconds: int, label: str):
    if not _HAS_ALARM:
        yield
        return

    def _handler(signum, frame):
        raise ModuleTimeoutError(f"Módulo '{label}' superó su tope de {seconds}s")

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def run_module(func, *args, timeout: int, label: str, on_error=None, **kwargs):
    """Ejecuta func(*args, **kwargs) con un tope de tiempo propio. Si
    falla o supera el tope, se registra (via on_error, si se pasa) y se
    devuelve None en vez de abortar el pipeline entero — el resto de
    módulos se ejecuta igualmente."""
    try:
        with _module_alarm(timeout, label):
            return func(*args, **kwargs)
    except ModuleTimeoutError as e:
        if on_error:
            on_error(f"⚠️ {e} — módulo omitido, se continúa con el resto del pipeline.")
        return None
    except Exception as e:
        if on_error:
            on_error(f"⚠️ Módulo '{label}' falló ({type(e).__name__}: {e}) — se omite.")
        return None
