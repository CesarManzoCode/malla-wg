# Changelog

## Sin publicar

- Un pong autenticado con la clave disco del par confirma como directa la dirección a la que se mandó su ping, aunque llegue desde otro origen, como pasa detrás de un NAT APDM; antes debía llegar desde esa misma dirección. Un pong que no abre con la clave del par, o cuyo txid no es de un ping pendiente, sigue sin confirmar nada. Se quitan de `matrix/findings.json` los 3 hallazgos del simulador que causaba la regla anterior; con la nueva, la matriz simulada debe coincidir con la teoría en las 185 celdas, lo que se midió antes con un cambio equivalente y aún no con este código (p03).
- Las pruebas de cookies bajo carga cuentan una inundación que no cumple el plazo de 1 s como intento no válido y la repiten, en vez de fallar por una máquina ocupada; el plazo, los intentos y el motivo están en un solo lugar (p02).
- critrun cuenta como aprobado el salto intencional de `TestForcedFailure`, la única excepción declarada, para que `make test-unpriv` no salga con 1 sobre la suite completa por él (p01).

### Matriz de NAT, mutantes y criterios globales (K3)

Cerrado el 2026-11-01 UTC sobre el commit `7a83990`: los 11 criterios de salida pasan, entre ellos la matriz de conexión directa en el simulador y en NATs reales de Linux, que coinciden con la teoría salvo 5 celdas explicadas en `matrix/findings.json`.

- Tabla teórica de NAT de 185 celdas (`matrix/theory.json`), generada desde las reglas de RFC 4787 del contrato y recalculada por separado en su prueba.
- NATs en el simulador: mapeo EIM, ADM y APDM, filtrado EIF, ADF y APDF por mapeo, hairpin, CGNAT anidado y timeout de mapeo por inactividad.
- La malla corre dentro del simulador con el mismo código del producto (`mesh.Core`), con la coordinación, el servicio reflexivo y el relay simulados. En las 185 celdas, con las semillas 1 a 8, la malla logra camino directo donde la teoría lo da, salvo en 3 celdas con APDM-EIF en los dos lados, que quedan en relay: la malla solo confirma un camino directo con un pong que vuelve desde la dirección a la que hizo ping.
- NATs reales con nftables en espacios de red para `none`, EIM-* y APDM-*, con sondeo de su mapeo, filtrado y hairpin: los 44 NATs sondeados tienen el comportamiento declarado. En la matriz real la malla coincide con la teoría salvo en 2 celdas con un lado APDM-EIF, donde logra camino directo y la teoría dice relay, porque Linux responde a un flujo entrante por el mismo puerto externo. Las celdas ADM, que nftables no puede expresar, se enumeran como sin oráculo real.
- Con NAT simétrico en los dos lados la malla queda en relay y el tráfico llega completo, en el simulador y con NATs reales.
- Mutantes `mutant_noreplay`, `mutant_norekey` y `mutant_nopunch` por etiquetas de compilación, sin cambio del producto sin ellas: los verificadores de anti-replay, de rekey y de la matriz detectan cada uno y nombran la propiedad violada.
- `verify/cmd/loc` cuenta las líneas de producto, apoyo y pruebas del producto: el simulador y los verificadores miden menos que la malla.
- `verify/cmd/deps` lista los módulos de la compilación y las pruebas con su licencia: todas son libres, ninguna es el SDK de una API de pago, y todo compila sin red.
- La suite completa corre sin espacios de red ni capacidades: ninguna prueba falla y los criterios que necesitan privilegios se saltan con `needs-privilege:`. `make test-unpriv` compila critrun y corre el binario, porque `go run` convierte su salida 77 en 1.

### Malla: coordinación, relay, traversal y CLI (K2)

Cerrado el 2026-11-01 UTC sobre el commit `5d64153`: los 6 criterios de salida pasan, entre ellos la transferencia por el relay HTTPS con todo el UDP bloqueado y la migración de relay a directo en plena transferencia sin pérdida, duplicación ni nuevo handshake.

- Servidor de coordinación HTTPS con registro, mapa de pares por long-poll, políticas con grupos y tags, revocación y servicio de endpoint reflexivo; el nodo sigue con el mapa en caché si la coordinación cae.
- Relay HTTPS con tramas propias que solo reenvía datagramas WireGuard o disco ya cifrados.
- Bind por par con endpoint ficticio: el dispositivo nunca ve la dirección real de un par, así que su sesión no depende del camino.
- Disco (ping, pong y CallMeMaybe cifrados con una clave propia por nodo), descubrimiento de endpoints y hole punching simultáneo.
- Elección de camino: el directo confirmado por un pong de hace menos de 5 s con menor RTT, si no el relay; latido cada 2 s, vuelta al relay sin pong en 5 s y reintento de punching cada 30 s. Un datagrama WireGuard que llega por UDP mientras el par va por el relay dispara un ping a esa dirección, para pasar a directo sin esperar el reintento.
- Migración sin corte: al cambiar de camino solo cambia el destino de salida; la entrada se acepta por los dos caminos y el handshake no se reinicia.
- Socket de control en `state_dir/control.sock` y CLI: `malla status [-json]` informa `direct` o `relay` por par, y `malla wait-direct -peer <nombre> -timeout <dur>` sale con 0 al lograr camino directo y con 1 al vencer el plazo.
- Un par sin autorización de la política no logra tráfico aunque conozca la clave; un par revocado sale del mapa, deja de recibir tráfico y no puede volver a registrarse con la misma clave; con la coordinación detenida, los pares ya conectados siguen intercambiando tráfico.
- Con todo el UDP bloqueado, 4 MiB pasan por el relay HTTPS con el mismo SHA-256, y la captura del relay solo contiene ciphertext WireGuard o disco.
- 16 MiB que empiezan por el relay pasan a camino directo en plena transferencia y llegan completos, sin duplicados y sin un nuevo handshake.

### Protocolo WireGuard e interoperabilidad (K1)

Cerrado el 2026-10-31 sobre el commit `a9e1610`: los 16 criterios de salida pasan, incluida la interoperabilidad contra el WireGuard del kernel y contra wireguard-go.

- Primitivas propias: X25519, ChaCha20-Poly1305, XChaCha20-Poly1305, BLAKE2s con y sin clave, HMAC-BLAKE2s y HKDF, con vectores RFC y Wycheproof.
- Noise_IKpsk2 con los cuatro mensajes de WireGuard, clave precompartida, mac1, mac2 y respuestas de cookie, TAI64N y ventana anti-replay de 8192 bits.
- Núcleo del dispositivo sin E/S: keypairs actual, anterior y siguiente, rekey por tiempo y por mensajes, reintentos, keepalive, roaming de endpoints, tabla de allowed-IPs, iniciaciones cruzadas y detección de carga con respuesta de cookie; avisa cuando acepta una cookie.
- Una respuesta de handshake cuenta como handshake enviado para el límite de una iniciación por REKEY_TIMEOUT, como en el kernel y en wireguard-go; sin eso dos pares cuyas iniciaciones se cruzan con la misma fase se seguían cruzando y no derivaban sesión (semilla 24 del lote de handshakes cruzados).
- Runtime real sobre UDP y TUN de Linux, modo estático de `malla up` y TUN en memoria para pruebas sin privilegios.
- Simulador determinista con semilla, enlaces con latencia, jitter y pérdida, y registro JSON Lines.
- Interoperable con el WireGuard del kernel de Linux y con wireguard-go en ambos sentidos: handshake y ping con el nodo propio como iniciador y como respondedor, clave precompartida, y respuesta de cookie bajo carga en los dos papeles.
- Un dato cifrado repetido contra el kernel se entrega una sola vez, y una sesión con el kernel pasa 200 s de tráfico a través de un rekey sin perder ninguno de 2000 pings.
- Plano de datos por TUN medido en espacios de red: enruta por allowed-IPs y descarta los paquetes cuyo origen no está en las allowed-IPs del par.

### Fundación (K0)

- Contrato del sistema: arquitectura sans-IO compartida por el runtime real y el simulador, protocolos de coordinación, relay HTTPS y disco, y matriz teórica de NAT de 185 celdas derivada de RFC 4787.
- Decisiones: Go 1.27; interoperabilidad sin sudo mediante espacios de usuario; wireguard-go y wgctrl fijados como oráculos dentro del proceso; ventana anti-replay de 8192 bits, como el kernel.
- Comando único de chequeo `make check` y CI que lo corre.
