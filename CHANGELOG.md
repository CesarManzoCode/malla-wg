# Changelog

## Sin publicar

### Fundación (K0)

- Contrato del sistema: arquitectura sans-IO compartida por el runtime real y el simulador, protocolos de coordinación, relay HTTPS y disco, y matriz teórica de NAT de 185 celdas derivada de RFC 4787.
- Decisiones: Go 1.27; interoperabilidad sin sudo mediante espacios de usuario; wireguard-go y wgctrl fijados como oráculos dentro del proceso; ventana anti-replay de 8192 bits, como el kernel.
- Comando único de chequeo `make check` y CI que lo corre.
