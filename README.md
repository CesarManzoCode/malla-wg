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
| K1 | Criptografía, protocolo WireGuard, simulador base, interoperabilidad con el kernel y wireguard-go, plano de datos | Cerrada |
| K2 | Coordinación y políticas, relay HTTPS, descubrimiento y hole punching, elección de camino, migración, CLI | Pendiente |
| K3 | Matriz de NAT (teoría, simulador, NATs reales), mutantes, conteo de líneas, dependencias, suite sin permisos | Pendiente |

## Resultados

### K1 (verificado el 2026-10-31 sobre el commit `a9e1610`)

Los 16 criterios de salida de K1 pasaron en una corrida sin `-short` que cuenta como fallo cualquier prueba saltada: las de espacios de red corrieron sin sudo.

| Qué se midió | Resultado |
| --- | --- |
| Vectores de RFC 7748, 8439, 7693 y 5869 (`make vectors`) | pasan |
| Wycheproof de X25519, ChaCha20-Poly1305 y XChaCha20-Poly1305, archivos con SHA-256 fijado | pasan |
| Primitivas, `noise` y `device` sin `crypto/*` (salvo `rand` y `subtle`), `golang.org/x/crypto` ni `golang.zx2c4.com` | se cumple |
| Constantes del protocolo y tamaños de los cuatro mensajes (148, 92, 64, 32 + carga) | coinciden |
| Handshake y ping con el WireGuard del kernel, con el nodo propio como iniciador y como respondedor | pasan |
| Handshake y ping con wireguard-go en los dos sentidos | pasan |
| Clave precompartida y respuesta de cookie bajo carga, contra el kernel y contra wireguard-go | pasan |
| Un dato cifrado enviado dos veces al kernel: `rx_packets` crece en 1 y llega una respuesta | pasa |
| Temporizadores de rekey en reloj simulado | coinciden |
| 200 s de tráfico con el kernel a través de un rekey: 2000 pings enviados, 2000 respondidos, handshake nuevo después del segundo 120 | pasa |
| Iniciaciones cruzadas en el simulador, semillas 1 a 32 | una sesión coherente en las 32 |
| Roaming: el endpoint sigue solo al origen autenticado | pasa |
| Plano de datos por TUN: enrutamiento por allowed-IPs y descarte de orígenes fuera de ellas | pasa |
| Simulador: misma semilla, mismo registro byte a byte; otra semilla, otro registro | pasa |
| Un fallo forzado imprime semilla y comando, y el comando lo repite | pasa |

Tiempos de esa corrida en esta máquina: `make check` 42.8 s (el paquete de interoperabilidad, 42.3 s) y el checker de K1 255.6 s.

La primera verificación de cierre falló y encontró un error real del dispositivo: dos pares cuyas iniciaciones se cruzaban en fase no derivaban sesión (semilla 24). Está corregido; el detalle está en el [CHANGELOG](CHANGELOG.md). Los límites que dejó K1 están en [`LIMITATIONS.md`](LIMITATIONS.md).

## Uso

```
make check
```

Corre formato, `go vet` y las pruebas en modo corto. Las pruebas que necesitan espacios de red no usan sudo: entran en un espacio de usuario sin privilegios y se saltan si el sistema no lo permite.
