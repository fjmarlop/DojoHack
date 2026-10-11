# DojoHack — contexto para Claude Code

Herramienta de reconocimiento para practicar CTF (HTB/THM/DockerLabs).
Lanzas el pipeline contra un target y te devuelve **pistas** sobre
posibles vulnerabilidades y técnicas a probar — nunca la solución
explícita — para que el usuario (Paco) siga resolviendo él mismo. Es
su actividad de relax/desconexión, secundaria a su preparación de la
TAI; sin prisa con este proyecto.

## Decisiones ya tomadas (no las reabras sin que Paco lo pida)

- **Proyecto totalmente aparte de PocketHacker** (su app/plataforma de
  pentesting móvil, repo hermano en `D:\proyectos\PocketHacker`,
  Android/Kotlin con backend Python en `pockethacker_debian`). No es
  un modo dentro de ese repo.
- **Clean-room completo**: PocketHacker depende de `wstg-scan`
  (repo de terceros) vía `importlib`, incluso para la lógica propia de
  las sondas de inyección (SSRF/SSTI/XSS/path traversal...). Para
  DojoHack esa lógica se **reescribe desde cero**, basándose en la
  metodología pública OWASP WSTG — no se copia ni se lee el código de
  wstg-scan para escribirla. Las herramientas externas (nmap, nuclei,
  ffuf, katana, dalfox, trufflehog, wpscan) se invocan directo por
  subprocess — ahí no hay ninguna dependencia que evitar, nunca ha
  sido código de wstg-scan.
- **Arsenal completo**, sin recortar por tratarse de CTF — en labs
  locales un escaneo completo no tarda tanto como para justificar
  simplificar.
- **Pipeline automático de punta a punta**: se lanza con
  `dojohack <target>` y corre todos los módulos encadenados sin pedir
  confirmaciones (a diferencia de PocketHacker, que sí las pide —
  aquí no hace falta ese nivel de control porque es el propio target
  de práctica de Paco, no una auditoría a un cliente real).
- **Feedback en vivo por stdout** mientras corre cada módulo (qué está
  haciendo, cuándo termina), sin necesidad de que el usuario toque
  nada — pero sin bloquear si algo tarda.
- **Timeout por módulo** (no solo un timeout global): cada módulo
  tiene su propio tope, así uno que se cuelgue no se lleva el pipeline
  entero. Patrón ya portado en `dojohack/timeouts.py`
  (`run_module`/`MODULE_TIMEOUTS`/`ModuleTimeoutError` — ver ese
  fichero para el porqué de cada detalle, incluido el aviso de que
  `signal.SIGALRM` solo existe en Unix).
- **Las pistas finales nunca distinguen "confirmado" vs "heurístico"**
  en el texto — todas se redactan igual de dubitativas ("por aquí hay
  algo, podría ser X o Y"), aunque la confianza SÍ se calcula
  internamente para decidir qué hallazgos merecen aparecer como pista
  y cuáles son ruido. El objetivo es no quitarle a Paco el esfuerzo de
  descubrir qué es real.
- **Dos fuentes de pistas, no una sola tabla**:
  1. Hallazgo con evidencia real de una herramienta (ej. SSTI
     confirmado por una sonda propia) → plantilla por tipo de
     vulnerabilidad, pero redactada como pista, no como hallazgo de
     auditoría.
  2. Descubrimiento en bruto por patrón de ruta/nombre (ej. ffuf
     encuentra `login.php` → sugerir "aquí podría valer la pena
     probar SQLi o fuerza bruta" como técnicas, sin confirmar nada
     todavía). Esta tabla aún no existe — hay que construirla.
- **Salida: terminal + fichero `.md` en paralelo** (para su flujo
  habitual de writeups en Obsidian), nunca HTML con plantilla de
  informe de cliente — eso es el lenguaje de PocketHacker, no de
  DojoHack.

## Qué se reutiliza de PocketHacker y qué no

Sí (código propio, nada que ver con wstg-scan):
- El patrón de timeout por módulo (ya portado, ver arriba).
- `preprocessor.py` (agrupación de duplicados + detección de
  confianza por reglas) — portar casi tal cual cuando toque esa fase;
  vive en `D:\proyectos\PocketHacker\pocketHacker_debian\preprocessor.py`
  si hace falta consultarlo.
- El esqueleto de `rule_classifier.py` (patrón→plantilla por tipo de
  vulnerabilidad) — mismo esqueleto, redacción distinta (pista, no
  recomendación de auditoría).

No:
- Nada de `wstg-scan` (ni el repo, ni importarlo, ni mirar su código
  para las sondas propias).
- Docker + API + WebSocket + gestión de jobs (`main.py`, `jobs.py` de
  PocketHacker) — DojoHack es CLI directa, uso interactivo de una sola
  persona, sin necesidad de esa capa.
- Informe HTML con plantilla profesional — aquí el informe es para
  practicar, no para un cliente.

## Estado actual del pipeline

```
dojohack/
  cli.py              — entrypoint: python -m dojohack.cli <target>
  timeouts.py          — run_module/MODULE_TIMEOUTS, ya listo
  modules/
    nmap_scan.py        — hecho, primer módulo (XML de nmap → findings)
```

Hallazgos en formato `{"name", "detail", "severity"}` — mismo convenio
que `preprocessor.py` de PocketHacker, para portar esa fase sin tener
que tocar la normalización.

## Próximos pasos, en orden

1. **nuclei** — siguiente módulo "fácil" (binario externo). Añadir
   `MODULE_TIMEOUTS["nuclei"]` y `modules/nuclei_scan.py`, mismo
   convenio de salida.
2. **ffuf** (fuzzing de directorios) — necesita wordlist (ver cómo
   resolvía esto PocketHacker con seclists/tiers si hace falta
   referencia, pero sin copiar su código).
3. **katana, dalfox, trufflehog, wpscan** — mismo patrón, uno a uno,
   probando cada uno contra un target real del lab antes de pasar al
   siguiente.
4. **Sondas propias de inyección** (SSTI/SSRF/XSS/path traversal) —
   la parte larga de verdad: diseñar e implementar desde la
   metodología OWASP WSTG, sin mirar wstg-scan. Empezar por una sola
   (ej. SSTI, ya hay plantilla de redacción de referencia) antes de
   abordar el resto.
5. **Preprocessor** — portar agrupación + confianza.
6. **Tabla de pistas por patrón de ruta/nombre** (login.php → SQLi/
   fuerza bruta, etc.) — construir desde cero, no existe aún en
   PocketHacker.
7. **Clasificador de pistas** — redacción dubitativa uniforme, sin
   distinguir confirmado/heurístico en el texto.
8. **Informe final** — terminal + `.md`.

## Al trabajar en este proyecto

- Ir módulo a módulo, probando cada uno contra un target real del lab
  antes de sumar el siguiente — no escribir todo el pipeline de golpe
  sin poder validarlo.
- Cualquier decisión de diseño nueva (no cubierta arriba) que afecte
  al alcance o la filosofía del proyecto: preguntar a Paco antes de
  asumir, no decidir por él.
- Commits pequeños, uno por módulo o pieza funcional.
