# malla-wg

Una malla VPN tipo Tailscale escrita desde cero en Go: WireGuard en espacio de usuario con criptografía propia, plano de datos por TUN, traversal de NAT con elección de camino y migración de relay a directo sin corte, relay de respaldo por HTTPS y un servidor de coordinación con claves, mapa de pares y políticas de acceso.

Su corrección se demuestra con mediciones externas y reproducibles:

- **Interoperabilidad byte a byte** con el WireGuard del kernel de Linux y con wireguard-go, en ambos sentidos, con clave precompartida y con cookies.
- **Matriz de conexión directa** entre tipos de NAT (mapeo × filtrado de RFC 4787, hairpin y CGNAT), que debe coincidir con la matriz teórica en un simulador determinista con semilla y en NATs reales de Linux armados en espacios de red.

El diseño y las decisiones están en [`vault/CONTRACT.md`](vault/CONTRACT.md), y las fuentes en [`vault/RESEARCH.md`](vault/RESEARCH.md). Lo que el proyecto no demuestra está en [`LIMITATIONS.md`](LIMITATIONS.md).

## Estado por fase

| Fase | Contenido | Estado |
| --- | --- | --- |
| K0 | Fundación: contrato, investigación, plan | Hecha |
| K1 | Criptografía, protocolo WireGuard, simulador base, interoperabilidad con el kernel y wireguard-go, plano de datos | Pendiente |
| K2 | Coordinación y políticas, relay HTTPS, descubrimiento y hole punching, elección de camino, migración, CLI | Pendiente |
| K3 | Matriz de NAT (teoría, simulador, NATs reales), mutantes, conteo de líneas, dependencias, suite sin permisos | Pendiente |

## Resultados

Todavía no hay resultados medidos.

## Uso

```
make check
```

Corre formato, `go vet` y las pruebas en modo corto. Las pruebas que necesitan espacios de red no usan sudo: entran en un espacio de usuario sin privilegios y se saltan si el sistema no lo permite.
