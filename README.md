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
| K2 | Coordinación y políticas, relay HTTPS, descubrimiento y hole punching, elección de camino, migración, CLI | Cerrada |
| K3 | Matriz de NAT (teoría, simulador, NATs reales), mutantes, conteo de líneas, dependencias, suite sin permisos | Implementada, pendiente de cierre |

## Resultados

### K3 (implementado, pendiente de cierre)

Las pruebas de K3 están escritas y todavía no se corrieron: esta sección dice qué mide cada criterio y dónde se ve su resultado, no el resultado. Las cifras llegarán con el cierre.

| # | Qué mide | Dónde se ve |
| --- | --- | --- |
| 14 | Que `matrix/theory.json` tenga las 185 celdas de §4.3 del contrato y coincida con las reglas de §4.2 recalculadas por separado | `verify/matrix` `TestCritTheoryCoverage` |
| 15 | Que cada celda, con las semillas 1 a 8 en el simulador, dé lo que dice la teoría o esté registrada como hallazgo en `matrix/findings.json` | `verify/matrix` `TestCritSimMatrix`: una línea por grupo con corridas directas y por relay, y por cada celda que difiere, `seed=` y `repro:` |
| 16 | Lo mismo con NATs reales de nftables en espacios de red, en las celdas sin ADM | `verify/matrix` `TestCritLinuxMatrix`, que además enumera las celdas sin oráculo real |
| 17 | Que el mapeo, el filtrado y el hairpin que miden los sondeos en los NATs reales sean los del tipo pedido | `verify/matrix` `TestCritNATFidelity` |
| 18 | Que con NAT simétrico en los dos lados la malla quede en relay y el tráfico pase completo | `verify/matrix` `TestCritSymmetricRelaySim` y `TestCritSymmetricRelayLinux` |
| 27 | Que el verificador de anti-replay detecte un filtro que acepta todo (`-tags mutant_noreplay`) | `verify/mutants` `TestCritMutantAntiReplay`: la salida de `TestCritAntiReplayProperty` con `property anti-replay violated` |
| 28 | Que el verificador de rekey detecte un dispositivo sin rekey ni rechazo de sesiones viejas (`-tags mutant_norekey`) | `verify/mutants` `TestCritMutantRekey`: la salida de `TestCritRekeyTimers` con `property rekey violated` |
| 29 | Que la matriz simulada detecte un nodo que no manda pings (`-tags mutant_nopunch`) | `verify/mutants` `TestCritMutantHolePunch`: la salida de `TestCritSimMatrix` con `property nat-matrix violated` y las celdas directas según la teoría que quedaron en relay |
| 30 | Que el apoyo (`sim/`, `verify/`) tenga menos líneas de código que el producto (`internal/`, `cmd/`) | `go run ./verify/cmd/loc`: los tres totales y el porcentaje de apoyo sobre producto |
| 31 | Que toda dependencia de la compilación y de las pruebas tenga una licencia libre reconocida y ninguna sea el SDK de una API de pago, y que todo compile sin red | `go run ./verify/cmd/deps`: una línea por módulo con su licencia; compilación con `GOPROXY=off` |
| 32 | Que la suite completa corra sin espacios de red ni de usuario y que lo único no aprobado sean saltos `needs-privilege:` | `make test-unpriv`: una línea `<Prueba> pass\|skip\|fail` por prueba, de `verify/critrun` |

### K2 (verificado el 2026-11-01 UTC sobre el commit `5d64153`)

Los 6 criterios de salida de K2 pasaron en una corrida sin `-short` que cuenta como fallo cualquier prueba saltada, y en la misma corrida volvieron a pasar los 16 de K1.

| Qué se midió | Resultado |
| --- | --- |
| Política que permite solo A↔B: C, registrado y con la clave pública de B configurada, manda tráfico a B | no llega nada a B; el tráfico A↔B sí llega |
| Revocación de B con A↔B fluyendo | la clave de B sale del mapa de A (respuesta de la coordinación y caché en disco), el tráfico de A a B deja de llegar y volver a registrar la clave se rechaza |
| Coordinación detenida con A↔B conectados | cada datagrama entre A y B llega durante los 10 s medidos |
| Todo el UDP entre A y B descartado por un router en espacios de red: 4 MiB por TCP dentro del túnel | llegan por el relay HTTPS con el mismo SHA-256; en la captura del relay solo hay mensajes WireGuard o disco, ningún byte del texto plano y ningún mensaje que abra con una clave del relay |
| `malla wait-direct -timeout 5s` con UDP bloqueado | sale con distinto de 0 y `malla status` dice `relay` |
| `malla wait-direct -timeout 30s` después de quitar el bloqueo | sale con 0 y `malla status` dice `direct` con endpoint |
| 16 MiB por TCP a 1 MiB/s que empiezan por el relay; el bloqueo se quita a los 2 s | el camino pasa a directo durante la transferencia, llegan exactamente 16 MiB con el mismo SHA-256 y no hay ningún handshake ni rekey desde el cambio |

Tiempos de esa corrida en esta máquina: `make check` 45.1 s (el paquete de pruebas de extremo a extremo, 42.3 s; el de interoperabilidad, 43.7 s), el checker de K2 43.2 s y el de K1 256.1 s.

La primera verificación de cierre falló sin llegar a ejecutar la malla en las tres pruebas de red: iproute2 7.3 leía el nombre de interfaz `br` del arnés como la palabra clave `broadcast`. También fallaron dos pruebas unitarias por errores de sus propios escenarios. Se corrigieron el arnés y las dos pruebas; el código de la malla no cambió. Los límites que dejó K2 están en [`LIMITATIONS.md`](LIMITATIONS.md).

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

Otros comandos:

```
make vectors                  # vectores RFC y Wycheproof de las primitivas
make test-unpriv              # la suite completa sin espacios de red ni capacidades (§8 del contrato)
go run ./verify/cmd/loc       # líneas de producto, apoyo y pruebas del producto
go run ./verify/cmd/deps      # módulos de la compilación y las pruebas, con su licencia
go test -tags mutant_noreplay -run '^TestCritAntiReplayProperty$' ./internal/noise   # un mutante a mano: debe fallar
```

Un nodo de la malla se levanta con `malla up -config node.json` y abre un socket de control en `state_dir/control.sock`. Con el nodo corriendo:

```
malla status -config node.json            # una línea por par: <nombre> <addr> direct|relay <endpoint>
malla status -json -config node.json
malla wait-direct -peer b -timeout 30s -config node.json   # 0 al lograr camino directo, 1 al vencer el plazo
```
