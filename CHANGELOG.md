# Changelog

## Sin publicar

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
