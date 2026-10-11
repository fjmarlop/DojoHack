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

Primer corte, solo para validar el cableado del pipeline de punta a
punta antes de sumar el resto de módulos:

- [x] Esqueleto del proyecto + CLI
- [x] Wrapper de timeout por módulo (`run_module`/`MODULE_TIMEOUTS`)
- [x] Módulo nmap (binario externo, sin lógica propia que reescribir)
- [ ] nuclei / ffuf (dir + vhost) / katana / dalfox / trufflehog / wpscan
- [ ] Sondas propias: SSTI, SSRF, XSS, Path Traversal, etc.
- [ ] Preprocessor (agrupación + confianza) — portado de PocketHacker
- [ ] Clasificador de pistas (dos tablas: hallazgo con evidencia vs.
      patrón de ruta/nombre en bruto)
- [ ] Informe final en terminal + guardado en .md

## Uso (de momento)

```
python -m dojohack.cli <target>
```

Guarda los hallazgos crudos en `output/<target>/findings.json`.

## Requisitos

- Python 3.10+
- `nmap` instalado y en el PATH (pensado para correr en la VM Kali del
  lab de CTF, no en Windows — ver nota de timeouts en
  `dojohack/timeouts.py`)
