# Changelog

## Sin publicar

### Protocolo WireGuard e interoperabilidad (K1)

Implementado; las pruebas de interoperabilidad están escritas y se corren al cerrar K1, así que aquí no hay resultados medidos.

- Primitivas propias: X25519, ChaCha20-Poly1305, XChaCha20-Poly1305, BLAKE2s con y sin clave, HMAC-BLAKE2s y HKDF, con vectores RFC y Wycheproof.
- Noise_IKpsk2 con los cuatro mensajes de WireGuard, clave precompartida, mac1, mac2 y respuestas de cookie, TAI64N y ventana anti-replay de 8192 bits.
- Núcleo del dispositivo sin E/S: keypairs actual, anterior y siguiente, rekey por tiempo y por mensajes, reintentos, keepalive, roaming de endpoints, tabla de allowed-IPs, iniciaciones cruzadas y detección de carga con respuesta de cookie; avisa cuando acepta una cookie.
- Una respuesta de handshake cuenta como handshake enviado para el límite de una iniciación por REKEY_TIMEOUT, como en el kernel y en wireguard-go; sin eso dos pares cuyas iniciaciones se cruzan con la misma fase se seguían cruzando y no derivaban sesión (semilla 24 del lote de handshakes cruzados).
- Runtime real sobre UDP y TUN de Linux, modo estático de `malla up` y TUN en memoria para pruebas sin privilegios.
- Simulador determinista con semilla, enlaces con latencia, jitter y pérdida, y registro JSON Lines.
- Pruebas contra el WireGuard del kernel y wireguard-go en ambos sentidos: handshake, PSK, cookies bajo carga en los dos papeles, replay de un dato cifrado y 200 s de tráfico a través de un rekey.

### Fundación (K0)

- Contrato del sistema: arquitectura sans-IO compartida por el runtime real y el simulador, protocolos de coordinación, relay HTTPS y disco, y matriz teórica de NAT de 185 celdas derivada de RFC 4787.
- Decisiones: Go 1.27; interoperabilidad sin sudo mediante espacios de usuario; wireguard-go y wgctrl fijados como oráculos dentro del proceso; ventana anti-replay de 8192 bits, como el kernel.
- Comando único de chequeo `make check` y CI que lo corre.
