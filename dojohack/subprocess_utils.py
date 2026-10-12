"""
Sustituto de subprocess.run() que no deja huérfanos cuando el módulo
que lo invoca es interrumpido — típicamente por ModuleTimeoutError
(ver dojohack.timeouts), pero vale para cualquier excepción.

subprocess.run() no mata al proceso hijo si la espera se interrumpe
por una excepción: ModuleTimeoutError se lanza desde el handler de
SIGALRM mientras el binario externo (nmap, nuclei, ffuf, katana,
dalfox, trufflehog) sigue en marcha, y al propagarse hacia arriba deja
el proceso corriendo en segundo plano, sin que nadie vuelva a tocarlo
— justo lo que la idea de "timeout por módulo" pretendía evitar, salvo
que solo libera al *pipeline* de la espera, no a la máquina del
proceso real. Con 6 binarios externos en el pipeline (antes solo
nmap+nuclei) esto pesa más que al principio.

Todos los módulos de dojohack.modules deberían llamar a esto en vez de
subprocess.run() directamente.
"""

import subprocess


def run(args, **kwargs) -> subprocess.CompletedProcess:
    """Misma idea que subprocess.run(args, capture_output=True, ...),
    pero si communicate() es interrumpido por cualquier excepción
    (incluida ModuleTimeoutError, que hereda de BaseException, no de
    Exception — ver dojohack.timeouts) mata el proceso y lo espera
    antes de relanzar la excepción, en vez de dejarlo huérfano."""
    kwargs.pop("capture_output", None)  # siempre capturamos por nuestra cuenta
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    try:
        stdout, stderr = proc.communicate()
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
