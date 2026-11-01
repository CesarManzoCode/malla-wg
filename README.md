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
| K3 | Matriz de NAT (teoría, simulador, NATs reales), mutantes, conteo de líneas, dependencias, suite sin permisos | Cerrada |

## Resultados

### K3 (verificado el 2026-11-01 UTC sobre el commit `7a83990`)

Los 11 criterios de salida de K3 pasaron en una corrida sin `-short` que cuenta como fallo cualquier prueba saltada, y en la misma corrida volvieron a pasar los 16 de K1 y los 6 de K2.

| # | Qué se midió | Resultado |
| --- | --- | --- |
| 14 | `matrix/theory.json` contra las reglas de §4.2 del contrato, recalculadas por separado por la prueba y por el checker | las 185 celdas coinciden: pair 55 (35 directas), hairpin 18 (5), cgnat 80 (61), cgnat_same 32 (9) |
| 15 | Las 185 celdas en el simulador, con las semillas 1 a 8 | en el cierre de K3 coincidían con la teoría salvo 3 celdas registradas como hallazgo (`pair APDM-EIF\|APDM-EIF`, `pair APDM-EIF\|APDM-ADF` y `hairpin APDM-EIF\|hairpin=True`, en relay con las 8 semillas donde la teoría dice directo), porque el bind exigía que el pong llegara desde la dirección pingueada. Desde p03 confirma el destino del ping (D23 del contrato) y esos hallazgos se quitaron: con un cambio equivalente las 185 celdas coincidieron en una medición del fix de k3; con el código de p03 la matriz aún no se ha corrido |
| 16 | Las celdas sin ADM con NATs reales de nftables en espacios de red, `malla wait-direct -timeout 30s` en los dos nodos | coinciden con la teoría salvo 2 celdas registradas como hallazgo: `pair EIM-APDF\|APDM-EIF` y `pair APDM-EIF\|APDM-APDF` dan directo donde la teoría dice relay; la prueba enumera las celdas ADM-* sin oráculo real. Medido con la regla de confirmación de K3; con la de p03 (D23) no se ha vuelto a correr |
| 17 | Mapeo, filtrado y hairpin sondeados en los NATs reales de las 12 celdas hairpin y las 32 cgnat_same con oráculo real | los del tipo declarado en las 44 |
| 18 | NAT simétrico (APDM) en los dos lados | relay en los dos nodos; en el simulador llegan los 100 datagramas y en el NAT real 1 MiB con el mismo SHA-256 |
| 27 | `TestCritAntiReplayProperty` con `-tags mutant_noreplay` | falla y nombra `property anti-replay violated` |
| 28 | `TestCritRekeyTimers` con `-tags mutant_norekey` | falla y nombra `property rekey violated` |
| 29 | `TestCritSimMatrix` con `-tags mutant_nopunch` | falla con `property nat-matrix violated` y nombra al menos una celda directa según la teoría que quedó en relay |
| 30 | Líneas de código del apoyo (`sim/`, `verify/`) contra las del producto (`internal/`, `cmd/`), con `verify/cmd/loc` y con cloc | apoyo < producto con los dos contadores; el log del cierre no trae los totales |
| 31 | Licencias de los módulos de la compilación y las pruebas, y compilación con `GOPROXY=off` | todas reconocidas como libres, ningún SDK de API de pago, compila sin red |
| 32 | La suite completa dentro del entorno de §8 (sin espacios de red ni de usuario, sin capacidades, `GOPROXY=off`) | ninguna prueba falla y todos los criterios que se saltan dicen `needs-privilege:`; critrun sale con 77 en un criterio privilegiado y con 0 en uno sin privilegio |

Las diferencias de los criterios 15 y 16 están explicadas en `matrix/findings.json`; ninguna se arregló cambiando el producto. Tiempos de esa corrida en esta máquina: `make check` 89.9 s (el paquete de la matriz, 89.2 s), el checker de K3 671.6 s, el de K1 256.0 s y el de K2 43.0 s.

La primera verificación de cierre falló: nftables 1.1.7 rechazó las reglas de los NATs reales porque dos cadenas se llamaban `fwd` e `in`, palabras reservadas, así que ningún NAT real llegó a armarse; y la matriz simulada difería de la teoría en las 3 celdas de arriba. Se renombraron las cadenas, se registraron los 5 hallazgos, y el checker de la suite sin permisos pasó a correr critrun compilado, porque `go run` convierte cualquier salida distinta de 0 en 1. El código de la malla no cambió. Los límites que dejó K3, entre ellos que `make test-unpriv` sale con 1 sobre la suite completa, están en [`LIMITATIONS.md`](LIMITATIONS.md).

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
