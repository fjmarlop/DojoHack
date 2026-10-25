# DojoHack

Herramienta de reconocimiento para practicar CTF (HTB/THM/DockerLabs):
lanzas el pipeline contra un target, te devuelve pistas sobre posibles
vulnerabilidades y técnicas a probar — sin decirte explícitamente cómo
explotrarlas — y a partir de ahí resuelves tú.

Proyecto hermano de [PocketHacker](../PocketHacker), pero independiente:
clean-room completo, sin depender de wstg-scan ni de ningún repo de
terceros para la lógica de detección. Las herramientas externas (nmap,
nuclei, ffuf, katana, dalfox, trufflehog, wpscan) se invocan directo;
las sondas propias (SSTI/SSRF/XSS/path traversal...) se reescriben
desde la metodología OWASP WSTG.

## Estado actual

Hoja de ruta inicial completa, pipeline de punta a punta validado
contra un lab real:

- [x] Esqueleto del proyecto + CLI
- [x] Wrapper de timeout por módulo (`run_module`/`MODULE_TIMEOUTS`)
- [x] Preflight: comprueba e instala el arsenal vía apt si falta algo
- [x] Módulos de herramientas externas: nmap, nuclei, ffuf, katana,
      dalfox (acoplado a katana), trufflehog, wpscan (enumeración
      completa: plugins/temas/usuarios/backups — sin API token de
      wpscan.com todavía, así que sin cruce contra su base de CVEs)
- [x] Resolución de target web (`web_targets.py`): puerto/esquema a
      partir de lo que encuentra nmap + `--base-path` si la app no
      está en la raíz — validado contra dos labs reales (vhosting por
      nombre y WordPress en un subdirectorio)
- [x] Aviso de vhost equivocado (`vhost_check.py`) si target es una IP
      y huele a vhost por defecto
- [x] Sondas propias (OWASP WSTG, clean-room): SSTI, SSRF (con
      listener OOB propio para SSRF ciego), Path Traversal — XSS no
      tiene sonda propia porque dalfox ya la cubre
- [x] Tabla de pistas por patrón de ruta/nombre (`route_patterns.py`)
- [x] Preprocessor (agrupación + confianza) — portado de PocketHacker
- [x] Clasificador de pistas — redacción dubitativa uniforme
- [x] Informe final en terminal + guardado en `.md`
- [x] Detector de CVE-2026-109618/109619 ("PHP2Shell", RCE crítico en
      PHP 7.3–8.5.11, disclosure 2026-10-21) — `php_cve_check.py`,
      clean-room contra el advisory oficial de PHP Group, solo
      fingerprint de versión (sin disparar el bug de memoria de
      verdad, eso ya sería explotación)
- [x] Modo `--quick` (`quick_scan.py`) — diagnóstico de vhost/CMS en
      segundos, antes de lanzar el pipeline completo

Próximos pasos (sin hoja de ruta fija todavía): ampliar la tabla de
patrones de ruta y los redactores de pistas según lo que vaya
apareciendo en más labs, considerar un token de wpscan.com si hace
falta cruzar contra CVEs conocidos, y lo que surja al usarlo de verdad
en más CTFs.

## Instalación

```
cd DojoHack
pip install -e . --break-system-packages   # editable: los cambios en los .py se ven sin reinstalar
```

Deja `dojohack` como comando normal en el PATH (vía el entry point de
`pyproject.toml`), invocable desde cualquier carpeta — la carpeta de
salida sigue ancládose a la raíz del proyecto, no a donde se lance el
comando (ver `dojohack/cli.py`, `_PROJECT_ROOT`). Sin instalar,
`python -m dojohack.cli <target>` sigue funcionando igual, lanzado
desde la raíz del repo.

## Uso

```
dojohack <target> [--base-path /subdir] [--name nombre-maquina] [--polish]
dojohack <target> --quick
```

`--quick` hace un diagnóstico rápido (segundos, sin nmap ni fuzzing
con wordlist) de si `target` necesita vhosting por nombre y/o tiene
el CMS en un subdirectorio, e imprime el comando `dojohack` completo
recomendado — pensado para no relanzar el pipeline completo 2-3 veces
cuando el target usa vhosting (ver `quick_scan.py`). No toca
`/etc/hosts` ni lanza el resto del pipeline.

`--name` fija el nombre de la carpeta de salida (`output/<name>/` en
vez de `output/<target>/`) — para que coincida con el nombre que uses
en tu flujo de writeups aparte (`notas/<nombre-máquina>/` en `~/ctf`),
cuando `target` es una IP o un hostname largo distinto del nombre de
la máquina.

`--polish` pide al CLI local de Claude Code (`claude -p`, sin API de
pago ni `ANTHROPIC_API_KEY` — necesita el comando `claude` en PATH y
sesión iniciada en la máquina) que mejore la redacción de
`recon_writeup.md` — apagado por defecto, cae solo a la versión
determinista si algo falla (`claude` no está en PATH, timeout, error).
Si quien lanza `dojohack` es ya una sesión de Claude Code interactiva,
tampoco hace falta `--polish`: esa misma sesión puede pulir
`recon_writeup.md` directamente, a mano.

El target web real no siempre está en `http://target/` puerto 80: si
nmap encuentra varios puertos http(s), el pipeline los escanea todos;
si la app está en un subdirectorio (ej. un WordPress en `/wordpress`,
visto de primera mano en un lab real), `--base-path` lo indica. Si
`target` es una IP y la raíz huele a vhost por defecto (Apache/Nginx/
IIS placeholder), el pipeline avisa — puede que haga falta el hostname
real en vez de la IP (ver `dojohack/web_targets.py` y
`dojohack/vhost_check.py`).

Guarda en `<raíz del proyecto>/output/<target o name>/`:
- `findings.json` — hallazgos crudos de todos los módulos/sondas
- `preprocessed.json` — agrupados + confianza calculada
- `pistas.json` — pistas ya redactadas + contexto de reconocimiento
- `informe.md` — el mismo contenido que se imprime en terminal, listo
  para caer en un vault de Obsidian
- `recon_writeup.md` — el mismo contenido repartido en
  "Reconocimiento"/"Enumeración web", listo para pegar como "toma
  nota" en el flujo de writeups aparte de `~/ctf` (ver su CLAUDE.md) —
  DojoHack nunca escribe directamente en esas notas, solo deja el
  contenido listo para que Paco decida qué pegar

## Requisitos

- Python 3.10+ y las dependencias de `requirements.txt` (`httpx`,
  usado por las sondas propias)
- Kali Linux, con `nmap`, `nuclei`, `ffuf` + `seclists`, `katana`,
  `dalfox`, `trufflehog` y `wpscan` en el PATH — si falta alguno, el
  preflight del pipeline intenta instalarlo solo vía apt (necesita
  sudo interactivo, por eso hace falta una terminal real, no vale
  lanzarlo sin TTY)
- Pensado para correr en la VM Kali del lab de CTF, no en Windows —
  ver nota de timeouts en `dojohack/timeouts.py`
