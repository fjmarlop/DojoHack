# DojoHack — contexto para Claude Code

Herramienta de reconocimiento para practicar CTF (HTB/THM/DockerLabs).
Lanzas el pipeline contra un target y te devuelve **pistas** sobre
posibles vulnerabilidades y técnicas a probar — nunca la solución
explícita — para que quien lo use siga resolviendo por su cuenta.
Proyecto personal, sin prisa.

## Decisiones ya tomadas (no las reabras sin consultarlo antes)

- **Clean-room completo**: cero dependencia de `wstg-scan` ni de
  ningún otro repo de terceros para la lógica de detección. Las
  sondas propias (SSTI/SSRF/SQLi/command injection/path traversal) se
  reescriben desde cero a partir de la metodología pública OWASP
  WSTG — no se copia ni se lee código ajeno para escribirlas. Las
  herramientas externas (nmap, nuclei, ffuf, katana, dalfox, arjun,
  enum4linux-ng, testssl, trufflehog, wpscan) se invocan directo por
  subprocess — ahí no hay ninguna dependencia que evitar.
- **Arsenal completo**, sin recortar por tratarse de CTF — en labs
  locales un escaneo completo no tarda tanto como para justificar
  simplificar.
- **Pipeline automático de punta a punta**: se lanza con
  `dojohack <target>` y corre todos los módulos sin pedir
  confirmaciones — no hace falta ese nivel de control porque el
  target es siempre el propio lab de práctica, nunca una auditoría a
  un cliente real.
- **Feedback en vivo por stdout** mientras corre cada módulo (qué está
  haciendo, cuándo termina), sin bloquear si algo tarda.
- **Timeout por módulo** (no solo un timeout global): cada módulo
  tiene su propio tope, así uno que se cuelgue no se lleva el pipeline
  entero. Ver `dojohack/timeouts.py` (`run_module`/`run_threadsafe`/
  `MODULE_TIMEOUTS`/`ModuleTimeoutError`) para el porqué de cada
  detalle, incluido el aviso de que `signal.SIGALRM` solo existe en
  Unix (de ahí `run_threadsafe`, sin señales, para los módulos que
  corren en paralelo).
- **Las pistas finales nunca distinguen "confirmado" vs "heurístico"**
  en el texto — todas se redactan igual de dubitativas ("por aquí hay
  algo, podría ser X o Y"), aunque la confianza SÍ se calcula
  internamente para decidir qué hallazgos merecen aparecer como pista
  y cuáles son ruido. El objetivo es no quitarle al usuario el
  esfuerzo de descubrir qué es real.
- **Dos fuentes de pistas, no una sola tabla**:
  1. Hallazgo con evidencia real de una herramienta (ej. SSTI
     confirmado por una sonda propia) → plantilla por tipo de
     vulnerabilidad, pero redactada como pista, no como hallazgo de
     auditoría.
  2. Descubrimiento en bruto por patrón de ruta/nombre (ej. ffuf
     encuentra `login.php` → sugerir "aquí podría valer la pena
     probar SQLi o fuerza bruta" como técnicas, sin confirmar nada
     todavía) — ver `route_patterns.py`.
- **Salida: terminal + fichero `.md` en paralelo**, pensada para
  pegarse directo en un vault de notas (Obsidian u otro) — nunca HTML
  con plantilla de informe de cliente, aquí el informe es para
  practicar, no para un cliente.

## Al trabajar en este proyecto

- Ir módulo a módulo, probando cada uno contra un target real del lab
  antes de sumar el siguiente — no escribir todo el pipeline de golpe
  sin poder validarlo.
- Cualquier decisión de diseño nueva (no cubierta arriba) que afecte
  al alcance o la filosofía del proyecto: preguntar antes de asumirla,
  no decidir unilateralmente.
- Commits pequeños, uno por módulo o pieza funcional.

Para el estado actual del pipeline y los próximos pasos, ver
[README.md](README.md) — se mantiene ahí para no duplicar y que no se
desincronicen.
