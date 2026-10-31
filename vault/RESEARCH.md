# Investigación: fuentes primarias con revisión fijada

Todas las fuentes se consultaron el 2026-10-31. Los RFC son inmutables por número. Las páginas web sin control de versiones llevan el SHA-256 del contenido descargado ese día. La investigación previa de la idea está fuera del repositorio; aquí solo entran las fuentes que el contrato usa.

## Protocolo WireGuard

| Fuente | Revisión fijada | Qué se tomó |
| --- | --- | --- |
| https://www.wireguard.com/protocol/ | HTML del 2026-10-31, SHA-256 `c8f084a0f72e362bad6d1bb65e3625fde4ee32a0b7ee97dcf940b19a7c225bf1` | CONSTRUCTION (37 bytes), IDENTIFIER (34 bytes), `mac1----`, `cookie--`, `MAC = Keyed-Blake2s(key, input, 16)`, `HMAC = HMAC-Blake2s(…, 32)`, formato de los mensajes, reglas de rekey |
| Kernel Linux, `drivers/net/wireguard/` (`messages.h`, `noise.c`, `cookie.c`, `receive.c`, `send.c`, `timers.c`) en https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git | etiqueta `v7.2.11` (el kernel que corre en esta máquina, `7.2.11-arch1-1`) | `COUNTER_BITS_TOTAL = 8192`, ventana `8192 − BITS_PER_LONG`, REKEY/REJECT/KEEPALIVE, `REKEY_TIMEOUT_JITTER_MAX_JIFFIES = HZ/3`, `MAX_QUEUED_INCOMING_HANDSHAKES = 4096`, rekey en recepción a `REJECT − KEEPALIVE − REKEY_TIMEOUT`, puntos donde cambia el endpoint |
| wireguard-go, módulo `golang.zx2c4.com/wireguard` | `v0.0.0-20261024220952-b3bc704ef0ee` (2026-10-24) | `device/constants.go` (mismas constantes), `replay/replay.go` (ventana `(128−1)·64`), `tun/netstack` |
| `golang.zx2c4.com/wireguard/wgctrl` | `v0.0.0-20241231184526-a9ab2273dd10` | Configuración del enlace del kernel por netlink; probado dentro de un espacio de usuario |
| Noise Protocol Framework, https://noiseprotocol.org/noise.html | Revisión 34 | Patrón IK y modificador psk2 |
| Whitepaper de WireGuard, https://www.wireguard.com/papers/wireguard.pdf | PDF del 2026-10-31 (HTTP 200) | Contexto de diseño de cookies y temporizadores |

## Criptografía

| Fuente | Revisión fijada | Qué se tomó |
| --- | --- | --- |
| RFC 7748, https://www.rfc-editor.org/rfc/rfc7748.txt | RFC 7748 | X25519 y vectores §5.2 y §6.1 |
| RFC 8439, https://www.rfc-editor.org/rfc/rfc8439.txt | RFC 8439 | ChaCha20, Poly1305, AEAD y vectores §2.x y Apéndice A |
| draft-irtf-cfrg-xchacha-03, https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03 | versión -03 | HChaCha20 y XChaCha20-Poly1305 (construcción; los vectores salen de Wycheproof) |
| RFC 7693, https://www.rfc-editor.org/rfc/rfc7693.txt | RFC 7693 | BLAKE2s, ejemplo del Apéndice B y auto-test del Apéndice E (con y sin clave) |
| RFC 2104, https://www.rfc-editor.org/rfc/rfc2104.txt | RFC 2104 | HMAC |
| RFC 5869, https://www.rfc-editor.org/rfc/rfc5869.txt | RFC 5869 | HKDF y vectores del Apéndice A (la estructura se aplica con HMAC-BLAKE2s en WireGuard) |
| Wycheproof, https://github.com/C2SP/wycheproof | commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` (2026-10-23), licencia Apache-2.0 | `testvectors_v1/x25519_test.json` (518 pruebas) SHA-256 `35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d`; `testvectors_v1/chacha20_poly1305_test.json` (325) SHA-256 `fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d`; `testvectors_v1/xchacha20_poly1305_test.json` (315) SHA-256 `a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9` |

## NAT

| Fuente | Revisión fijada | Qué se tomó |
| --- | --- | --- |
| RFC 4787, https://www.rfc-editor.org/rfc/rfc4787.txt | RFC 4787, texto SHA-256 `5db82ec5f0d6b9b0fc0a37ce7d5b40592e4e6f41562ba8fbc55f1daa52648405` | Mapeo EIM/ADM/APDM (§4.1), filtrado EIF/ADF/APDF (§5), hairpinning y REQ-9a (§6), timer de mapeo y REQ-5 (§4.3), nota de REQ-8 sobre ICE con APDF |
| RFC 6598, https://www.rfc-editor.org/rfc/rfc6598.txt | RFC 6598 | `100.64.0.0/10` para CGNAT |
| Blog de Tailscale, https://tailscale.com/blog/nat-traversal-improvements-pt-1 | página del 2026-10-31 (fuente de contexto, no normativa) | Hole punching simultáneo y relay como último recurso |

## Herramientas de esta máquina (verificadas con `--version` el 2026-10-31)

| Herramienta | Versión | Uso |
| --- | --- | --- |
| Go | go1.27.3 linux/amd64 | Lenguaje (D01) |
| `math/rand/v2` | Go 1.27.3: `NewChaCha8(seed [32]byte)`, `(*ChaCha8).Read`, `NewPCG` | Aleatoriedad del simulador |
| nftables | v1.1.7 | NATs reales (§4.4 del contrato) |
| iproute2 | 7.3.0 | Espacios de red, veth |
| util-linux (`unshare`, `setpriv`) | 2.42.4 | Espacios de usuario y entorno sin permiso |
| Python | 3.14.8 | Checkers |
| GNU Make | 4.4.1 | `make check` |
| cloc | 2.10 | Contraste del conteo de líneas |
| Kernel | 7.2.11-arch1-1, módulo `wireguard` 1.0.0 | Oráculo |
| No instalados | `wg`, `wireguard-go` (binario), `tcpdump`, `iperf3`, `tailscaled`, `headscale` | Se evitan (D09, D10, D14, D21) |

## CI

| Fuente | Revisión fijada |
| --- | --- |
| `actions/checkout` | `v7.0.1` (commit `3d3c42e5aac5ba805825da76410c181273ba90b1`), runtime node24 |
| `actions/setup-go` | `v7.0.0` (commit `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`), entrada `go-version` |
| `actions/go-versions` manifest | incluye `1.27.3` |

## Vacante

| Fuente | Consulta |
| --- | --- |
| https://boards-api.greenhouse.io/v1/boards/tailscale/jobs | 2026-10-31: 58 vacantes; Networking (Dataplane) en Remote (United States), id 4732897005, y Remote (Canada), id 4732874005 |
