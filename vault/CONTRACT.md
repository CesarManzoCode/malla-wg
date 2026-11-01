# Contrato de malla-wg

Fecha del contrato: 2026-10-31 (K0). Etiquetas: **[hecho]** se observó en esta máquina o en una fuente primaria fijada en `vault/RESEARCH.md`; **[diseño]** es una decisión aceptada aquí; **[hipótesis]** está pendiente de medirse en el K indicado.

## 1. Qué debe hacer el sistema

malla-wg es una malla VPN tipo Tailscale escrita desde cero en Go. El producto es la malla:

1. **WireGuard en espacio de usuario**: handshake Noise_IKpsk2, mensajes de cookie (mac1, mac2 y respuesta de cookie), rekey por tiempo y por número de mensajes, ventana anti-replay, roaming de endpoints, interoperable byte a byte con el WireGuard del kernel de Linux y con wireguard-go.
2. **Criptografía propia**: X25519, ChaCha20-Poly1305, XChaCha20-Poly1305 (la exige la respuesta de cookie), BLAKE2s con y sin clave, HMAC-BLAKE2s y HKDF, sin usar primitivas de la biblioteca estándar ni de `golang.org/x/crypto`.
3. **Plano de datos por TUN**: enrutamiento saliente por allowed-IPs (prefijo más largo) y descarte entrante de todo paquete cuyo origen no esté en las allowed-IPs del par que lo descifró.
4. **Traversal de NAT**: descubrimiento de endpoints (local y reflexivo), hole punching simultáneo, elección de camino entre directo y relay, y migración de relay a directo sin cortar la sesión.
5. **Relay de respaldo sobre HTTPS** que reenvía solo ciphertext de WireGuard cuando el UDP directo está bloqueado.
6. **Servidor de coordinación**: registro de nodos, distribución de claves públicas y del mapa de pares, políticas de acceso, revocación, y caché local en los nodos para seguir funcionando si cae.
7. **Herramienta de línea de comandos** `malla`: levanta el nodo, informa el camino de cada par (`direct` o `relay`) y espera hasta lograr camino directo.

El apoyo, que no es producto y debe medir menos líneas que él: un simulador de red determinista con semilla, el armado de NATs reales de Linux en espacios de red, los verificadores de la matriz y de las propiedades, los mutantes y los scripts de conteo y licencias.

Fuera de alcance (decidido por la idea): predicción de puertos con paradoja del cumpleaños, IPv6 con traducción de prefijos y pruebas en internet real.

## 2. Arquitectura

### 2.1 Módulo y paquetes [diseño]

Un solo módulo Go: `github.com/CesarManzoCode/malla-wg`, con `go 1.27` en `go.mod`.

| Ruta | Rol | Contenido |
| --- | --- | --- |
| `internal/x25519`, `internal/chachapoly`, `internal/blake2s`, `internal/hkdf` | producto | Primitivas. `chachapoly` incluye XChaCha20-Poly1305 (HChaCha20). `blake2s` admite clave de 0 a 32 bytes y salida de 1 a 32 bytes. `hkdf` incluye HMAC-BLAKE2s. |
| `internal/noise` | producto | Formato de los cuatro mensajes, handshake IKpsk2, mac1/mac2, respuesta de cookie, TAI64N, ventana anti-replay, cifrado de transporte. |
| `internal/device` | producto | Núcleo sans-IO del dispositivo: pares, keypairs (`current`, `previous`, `next`), temporizadores, rekey, keepalive, roaming, tabla de allowed-IPs, iniciaciones cruzadas. |
| `internal/tun` | producto | TUN de Linux (`/dev/net/tun`, `IFF_TUN|IFF_NO_PI`) y TUN en memoria para pruebas sin privilegio. |
| `internal/runtime` | producto | Bucle de eventos real: sockets UDP, TUN, reloj del sistema y `crypto/rand`, que alimentan al núcleo sans-IO. |
| `internal/coord` | producto | Servidor y cliente de coordinación, políticas, revocación, caché del mapa, servicio de endpoint reflexivo. |
| `internal/relay` | producto | Servidor y cliente del relay HTTPS. |
| `internal/magic` | producto | Disco (ping, pong, call-me-maybe), descubrimiento de endpoints, hole punching, elección de camino, migración; es el `bind` que decide a dónde va cada paquete cifrado. |
| `internal/mesh` | producto | Orquesta un nodo: cliente de coordinación, dispositivo, `magic`, relay, filtro de política y socket de control. |
| `cmd/malla`, `cmd/malla-coord`, `cmd/malla-relay` | producto | Binarios. |
| `sim` | apoyo | Simulador determinista: planificador de eventos, reloj virtual, enlaces, modelos de NAT, registro de eventos. |
| `verify/netns`, `verify/interop`, `verify/e2e`, `verify/props`, `verify/matrix`, `verify/mutants`, `verify/critrun`, `verify/cmd/loc`, `verify/cmd/deps` | apoyo | Arnés de espacios de red, pruebas de interoperabilidad, pruebas extremo a extremo, propiedades, matriz, mutantes, envoltorio de códigos de salida, conteo de líneas y licencias. |
| `matrix/theory.json`, `matrix/findings.json` | datos | Tabla teórica de NAT y archivo de hallazgos, versionados. |

**API de X25519 y de los AEAD** [diseño, k1-01]: `x25519.X25519(scalar, point [32]byte) ([32]byte, error)` devuelve `x25519.ErrZeroSharedSecret` y ceros si el resultado es todo ceros; ignora el bit 255 de `u` y acepta `u` no canónicos (RFC 7748 §5). `chachapoly.Seal`/`Open` (nonce de 12 bytes) y `chachapoly.XSeal`/`XOpen` (nonce de 24) tienen la forma `(dst, key, nonce, texto, ad []byte) ([]byte, error)`, agregan el resultado a `dst` como `cipher.AEAD`, rechazan claves que no sean de 32 bytes (`ErrKeySize`), nonces de otro tamaño (`ErrNonceSize`) y textos de más de (2^32 − 1)·64 bytes, para que el contador de bloque no dé la vuelta (`ErrTooLarge` en `Seal`), y si la etiqueta no verifica devuelven `ErrOpen` sin escribir en `dst`.

**API de BLAKE2s y HKDF** [diseño, k1-02]: `blake2s.New(tamaño, clave) (hash.Hash, error)` acepta salida de 1 a 32 bytes (`ErrSize`) y clave de 0 a 32 (`ErrKeySize`); `blake2s.New256()` es el constructor sin clave que se pasa a HMAC y HKDF; `blake2s.Sum256(datos) [32]byte`; `blake2s.MAC(clave, datos) [16]byte` es `Keyed-Blake2s(clave, datos, 16)` y entra en pánico con una clave de más de 32 bytes, porque en WireGuard la clave siempre es de 32 (mac1) o de 16 (mac2). `hkdf.NewHMAC(func() hash.Hash, clave) hash.Hash` sigue RFC 2104; `hkdf.Extract(h, sal, ikm)` reemplaza una sal vacía por `HashLen` ceros (RFC 5869 §2.2); `hkdf.Expand(h, prk, info, largo)` devuelve `ErrLength` si `largo` es negativo o supera 255·`HashLen`; `hkdf.HMACBlake2s(clave, datos...) [32]byte` y `hkdf.KDF1/KDF2/KDF3(clave, entrada)` devuelven arreglos de 32 bytes y calculan τ1…τn como la página del protocolo, que equivale a HKDF con la clave de encadenamiento como sal e `info` vacía.

**API de noise** [diseño, k1-03]: `noise.NewLocal(privada)` es la identidad estática del nodo y responde por el lado receptor de mac1, mac2 y la respuesta de cookie; `Local.NewPeer(pública, psk)` crea el estado por par (psk en ceros si no hay) y falla si el DH estático-estático da cero. Los índices de emisor los elige quien llama (`CreateInitiation` y `CreateResponse` reciben `sender`), porque la tabla de índices es del dispositivo. TAI64N necesita hora de pared: `CreateInitiation` recibe, además de `now` monotónico, `wall` en nanosegundos Unix, y los nanosegundos se redondean hacia abajo a múltiplos de 2^24 como el kernel y wireguard-go. `ConsumeInitiation` encuentra al par con una función `lookup(clave estática)`, rechaza un timestamp no mayor que el último aceptado de ese par (`ErrStaleTimestamp`) y, como `wg_noise_handshake_consume_initiation` del kernel, una iniciación a menos de 20 ms (1 s / INITIATIONS_PER_SECOND) de la última aceptada (`ErrFlood`). La cookie es `MAC(secreto de 32 bytes, IP de origen de 4 o 16 bytes (una IPv4 mapeada se desmapea) || puerto big-endian)`, como `make_cookie` del kernel; el secreto se renueva de forma perezosa al usarse con 120 s o más, y el iniciador deja de poner mac2 cuando su cookie cumple 115 s (COOKIE_SECRET_MAX_AGE − COOKIE_SECRET_LATENCY). Se acepta una sola respuesta de cookie por mac1 enviado. El relleno de transporte sigue `calculate_skb_padding` del kernel: múltiplo de 16, sin pasar del MTU si se da uno (`mtu > 0`). `Keypair.Decrypt` abre el AEAD antes de pasar el contador por `ReplayFilter.ValidateCounter(contador, RejectAfterMessages)`, para que un paquete falsificado no mueva la ventana.

**API de device** [diseño, k1-04]: `device.New(Config)` con clave privada, pares (`PublicKey`, `PresharedKey` en ceros si no hay, `AllowedIPs`, `Endpoint` opcional, `PersistentKeepalive` opcional), `Rand`, `MTU` del relleno (0 = múltiplo de 16), `ForceUnderLoad` y `WallOffset`: el TAI64N usa `now + WallOffset`, porque el núcleo no lee la hora de pared y `internal/runtime` fija el desfase al arrancar. `HandleUDP`, `HandleTUN` y `Tick` devuelven `Output{Datagrams, Packets, Events}`; `NextDeadline()` devuelve `device.Never` (`MaxInt64`) si no hay temporizador armado. Hay un evento `rekey` por cada iniciación enviada, con el motivo (`nokeypair`, `retry`, `sendage`, `sendmessages`, `receiveage`, `noreply`), y los `drop` llevan un motivo fijo (`allowedips`, `expired`, `decrypt`, `replay`, `cookie`, …). Una respuesta enviada cuenta, como en el kernel y en wireguard-go, para el límite de una iniciación por REKEY_TIMEOUT; sin eso dos pares cuyas iniciaciones se cruzan en fase siguen cruzándose. Los reintentos se cortan por tiempo: no se envía ninguna iniciación una vez pasados REKEY_ATTEMPT_TIME (90 s) desde la primera del intento; el kernel, en cambio, cuenta reintentos contra MAX_TIMER_HANDSHAKES (90/5 = 18), así que con el jitter su último intento cae después de 90 s, y el criterio 10 pide parar a los 90 s. La carga se mide como llegadas: el dispositivo está bajo carga si la más vieja de las últimas 512 llegadas de mensajes de handshake (tipos 1 a 3, antes de verificar mac1) tiene menos de 1 s, y sigue así 1 s más; el kernel usa en cambio la longitud de su cola. Las decisiones de rekey y de rechazo viven solas en `internal/device/rekey.go`, para el mutante `mutant_norekey`.

**Runtime, TUN y arnés** [diseño, k1-06]: `tun.Device` (`Name`, `Read`, `Write`, `Close`, un paquete IP por llamada) tiene dos implementaciones: `tun.OpenLinux(nombre)`, con `TUNSETIFF` e `IFF_TUN|IFF_NO_PI` y el descriptor no bloqueante para que `Close` desbloquee un `Read`, y `tun.NewMem(nombre, profundidad)`, con canales, `Inject` y `Outbound`, que como un TUN del kernel con la cola llena descarta lo que nadie lee y lo cuenta. `runtime.New(Config{Device, Conn, TUN, OnEvent})` fija `Rand = crypto/rand` y `WallOffset` a la hora de pared del arranque, y `now` son los nanosegundos monotónicos desde `New`; `Run` es el único bucle que toca el dispositivo (dos goroutines solo copian bytes del socket y del TUN hacia él), cierra socket y TUN al volver, cuenta los errores de escritura sin detenerse y `Query` ejecuta una función sobre el dispositivo dentro del bucle. `netns.Run` reconoce al hijo por la variable `MALLA_NETNS_CHILD` y lo re-ejecuta con `-test.run` restringido a la prueba, así que el código previo a `Run` corre en los dos procesos; el padre falla si el hijo falla o no corre la prueba. `netns.Do` deja el hilo bloqueado sin desbloquearlo, para que el runtime de Go lo descarte en vez de devolverlo al grupo dentro del espacio. `verify/critrun` cuenta como fallo una corrida sin pruebas, un fallo de paquete sin prueba fallida (compilación) y una prueba que empieza y no termina. En `TestCritDataplaneAllowedIPs` los «contadores de datagramas de cada socket» son `Udp InDatagrams` de `/proc/net/snmp` de cada espacio, porque el nodo es el único usuario de UDP en B y C; además se comprueba que A registró un `drop` con motivo `allowedips`.

**Interoperabilidad** [diseño, k1-07]: en cada prueba de `verify/interop` solo el lado que debe iniciar recibe el endpoint del otro, así que el otro no puede iniciar. Las claves se generan con `wgtypes`, que deriva la pública por su cuenta. El cliente `wgctrl` se crea dentro de `netns.Do`, porque su socket netlink queda en el espacio del hilo que lo crea, y cada subprueba usa espacios con nombre propio (`A1`, `B1`, …). «`LastHandshakeTime` distinto de cero» se lee igual en wireguard-go (`last_handshake_time_sec` de su UAPI). El rol del handshake se toma del primer evento `handshake` del nodo propio. El TUN en memoria responde ICMP echo con un ayudante de la prueba; netstack responde por su cuenta y hace ping con `DialPingAddr`, un socket por petición, porque `PingConn.Read` de netstack espera una notificación nueva y, con un socket compartido, las respuestas que llegan juntas (peticiones retenidas hasta el handshake) dejan las demás en cola detrás de respuestas viejas. Con PSK distintas la corrida falla si algún ping recibe respuesta, si el oráculo muestra un handshake o si el nodo propio deriva una sesión.

**Cookies, replay y rekey largo** [diseño, k1-08]: el dispositivo emite un evento `cookie` (`device.EventCookie`, también en el registro del simulador) cuando acepta una respuesta de cookie; «reenvía con mac2» se comprueba como la secuencia evento `cookie` → evento `rekey` → `handshake` como iniciador, porque `noise` pone mac2 en toda iniciación mientras la cookie tiene menos de 115 s. La inundación son 4096 copias de una sola iniciación, generada con `internal/noise` desde una clave que el oráculo no conoce, repartidas entre 4 sockets que envían en paralelo; el nodo propio arranca su handshake a mitad del envío del primer socket. Los sockets arrancan juntos y envían en lotes de 64 con `sendmmsg` (`ipv4.PacketConn.WriteBatch`). A mitad de su parte los cuatro se esperan y, durante 50 ms, cuentan las respuestas de cookie que reciben; si llegó alguna, el oráculo está bajo carga (el kernel y wireguard-go la mantienen 1 s después de detectarla) y el primero dispara al nodo propio, espera su evento `rekey`, y todos envían la segunda mitad. La pausa existe porque la cola de handshakes de wireguard-go tiene 1024 entradas y descarta lo que llega con ella llena: sin ella la iniciación del nodo propio se perdía casi siempre y su reintento, 5 s después, encontraba al oráculo ya fuera de carga. Si la primera mitad no recibió ninguna cookie, el oráculo no entró en carga y el intento no dice nada del nodo propio: `UnderLoadAttempts` repite la inundación con oráculo y nodo nuevos, a 1 s del intento anterior, hasta 10 veces, y la prueba falla si ninguna lo pone bajo carga; un intento con el oráculo bajo carga que falla hace fallar la prueba sin repetir. Con CPU contendida los trabajadores de handshake del kernel, que despierta cada llegada, drenan su cola más rápido de lo que llegan los datagramas y no siempre se alcanzan las 512 entradas que lo ponen bajo carga. Contra el kernel, la inundación sale de una segunda dirección de B (`192.168.50.3`), porque pasadas 2048 iniciaciones en cola el kernel limita la tasa por IP de origen y la iniciación del nodo propio no debe compartir ese cubo. Los pings que esperan un reintento (5 s) usan `ping -c 3 -w 20`. En `TestCritKernelReplay` la prueba no dispara temporizadores del dispositivo, así que entre las dos lecturas de `rx_packets` no sale nada más hacia A. En `TestCritKernelRekeyLong` los 2000 pings son `ping -q -c 2000 -i 0.1 -W 2` desde B, se cuentan con su línea de resumen y «posterior al segundo 120» se mide desde el primer ping.

### 2.2 Núcleos sans-IO [diseño]

`internal/noise`, `internal/device`, `internal/magic` y la lógica de `internal/coord` y `internal/relay` no abren sockets, no leen el reloj ni crean goroutines. Reciben `now` (nanosegundos monotónicos, `int64`), los bytes de entrada y una fuente de aleatoriedad `io.Reader`, y devuelven las salidas (datagramas, paquetes para el TUN, próximo vencimiento de temporizador). `internal/runtime` los conecta a sockets reales con un único bucle de eventos por nodo; `sim` los conecta a la red simulada. Así el simulador ejerce el mismo código que corre en producción. En el simulador la aleatoriedad sale de `math/rand/v2.ChaCha8` sembrado con la semilla. Ningún núcleo emite salidas en orden de iteración de un `map` sin ordenar antes.

### 2.3 Por qué el apoyo queda menor que el producto [diseño]

El simulador no reimplementa el protocolo: solo planifica eventos, mueve datagramas y modela NATs; el protocolo es el código del producto. Los verificadores son pruebas finas sobre ese código. El conteo (`verify/cmd/loc`) cuenta líneas de código Go no vacías y que no son solo comentario:

- producto = archivos `.go` que no son `_test.go` bajo `internal/` y `cmd/`;
- apoyo = todos los archivos `.go`, pruebas incluidas, bajo `sim/` y `verify/`;
- las pruebas unitarias del producto (`_test.go` bajo `internal/` y `cmd/`) no cuentan en ningún lado y se informan aparte.

Sale con 0 solo si apoyo < producto. El método fija como referencia de presupuesto un 15 % de código de verificación sobre producto; esa cifra se informa al cerrar cada K pero no es un gate.

## 3. Protocolos propios

Ninguno imita el formato de Tailscale. El formato oficial de las tramas DERP no se verificó (ver `vault/RESEARCH.md`), así que no se copia.

### 3.1 Coordinación [diseño]

HTTPS (TLS 1.3 de `crypto/tls` de Go) con certificado autofirmado ECDSA P-256 que el servidor genera al primer arranque. Los nodos fijan el SHA-256 del DER del certificado (`coord_fingerprint`). Cuerpos JSON.

| Método y ruta | Quién | Cuerpo y respuesta |
| --- | --- | --- |
| `POST /v1/register` | nodo | `{auth_key, node_key, disco_key, name, tags}` → `{node_id, token, addr}`. `addr` sale de `10.200.0.0/16`. Una clave revocada no puede registrarse otra vez. |
| `GET /v1/netmap?since=<v>` | nodo (`Authorization: Bearer <token>`) | Long-poll de hasta 25 s. → `{version, self, peers:[{node_id, name, node_key, disco_key, addr, endpoints}], relay}` con solo los pares que la política permite. |
| `POST /v1/endpoints` | nodo | `{endpoints:["ip:puerto", …]}`; sube la versión del mapa. |
| `PUT /v1/admin/policy` | admin (`Authorization: Bearer <admin_token>`) | Política completa. |
| `POST /v1/admin/revoke` | admin | `{node_id}`: el nodo sale de todos los mapas y su token deja de valer. |

**Servicio de endpoint reflexivo**, UDP en el mismo host (puerto por defecto 3478): petición `"mallaSTN"` (8 bytes) + `txid` (12 bytes); respuesta `"mallaSTN"` + `txid` + dirección observada (16 bytes IPv4-mapeada + 2 bytes de puerto big-endian). Sin autenticación, como STUN.

**Política** [diseño]: `{"groups": {"group:x": ["<nombre>", …]}, "rules": [{"src": [sel…], "dst": [sel…]}]}` con selectores `<nombre>`, `tag:<t>` o `group:<g>`. Denegar por defecto. Una regla permite el par en ambos sentidos. El mapa de un nodo solo incluye pares permitidos, y cada nodo además descarta en su filtro entrante el tráfico de pares no permitidos.

**Caché** [diseño]: el nodo guarda el último mapa en `state_dir/netmap.json` y en memoria; si la coordinación no responde, sigue con la caché sin expirarla.

**Servidor, cliente y nodo de malla** [diseño, k2-01]: la lógica es `coord.Core` (sin reloj, sockets ni goroutines; la aleatoriedad la da quien llama) y `coord.Server` la lleva por HTTPS, serializa las peticiones, guarda `state_dir/state.json` de forma atómica tras cada cambio y despierta los long-polls. El certificado vive en `state_dir/coord-cert.pem` y `coord-key.pem`; `coord_fingerprint` es el SHA-256 del DER en hexadecimal (se ignoran mayúsculas y `:`). El token son 32 bytes aleatorios en hexadecimal y el estado solo guarda su SHA-256. Volver a registrar una clave conocida conserva `node_id` y `addr` y emite un token nuevo que invalida el anterior; un nombre ya usado por otra clave se rechaza con 409; `addr` es `10.200.0.0 + node_id`. Las claves revocadas se guardan en el estado y su registro responde 403. `policy_file` solo se usa si el estado no tiene política: la de `PUT /v1/admin/policy` se persiste y gana. `GET /v1/netmap` responde enseguida si la versión es mayor que `since`; la versión es global, así que cualquier cambio despierta todos los long-polls. Un nodo reporta hasta 16 endpoints. Las respuestas del servicio reflexivo llegan al socket de WireGuard y `runtime.Config.Intercept` las aparta antes del dispositivo. En `internal/mesh` el filtro entrante es la tabla de pares del dispositivo: un par que sale del mapa se borra (`device.RemovePeer`: keypairs, handshake, paquetes en espera y allowed-IPs), así que sus iniciaciones no encuentran par y sus datos llevan índices desconocidos. El endpoint de un par solo se reemplaza cuando cambia el del mapa, para no deshacer el roaming. Un 401 hace que el nodo vuelva a registrarse; cualquier otro fallo se reintenta cada segundo sin tocar los pares. La clave disco se guarda en `state_dir/disco.key`. El mapa se aplica al dispositivo antes de escribirse en la caché.

### 3.2 Relay HTTPS [diseño]

TLS 1.3 de `crypto/tls`, certificado autofirmado con huella fijada (`relay_fingerprint`). El cliente abre `GET /v1/relay` con `Connection: Upgrade` y `Upgrade: malla-relay/1`; el servidor responde `101 Switching Protocols` y desde ahí fluyen tramas `[tipo u8][longitud u32 big-endian][carga]`:

| Tipo | Nombre | Carga |
| --- | --- | --- |
| 1 | ClientHello | node_key (32) |
| 2 | ServerHello | vacío |
| 3 | SendPacket | node_key destino (32) + datagrama |
| 4 | RecvPacket | node_key origen (32) + datagrama |
| 5 | KeepAlive | vacío |
| 6 | PeerGone | node_key (32) |

El relay solo reenvía datagramas WireGuard o disco ya cifrados; no tiene ninguna clave de sesión. Opción `capture_file` en el servidor: escribe cada carga reenviada (longitud u32 + bytes) para que la prueba la examine.

**Servidor y cliente del relay** [diseño, k2-02]: la lógica es `relay.Core` (sin reloj, sockets ni goroutines), que decide para una trama de una conexión qué tramas van a qué conexiones, y el códec (`AppendFrame`, `ParseFrame`, `ReadFrame`) trabaja sobre bytes, así que K3 puede llevar los dos al simulador; `relay.Server` y `relay.Client` los llevan por TLS. La carga de una trama es de hasta 32 + 65535 bytes; una trama más larga, una trama antes de ClientHello, un segundo ClientHello o un tipo que el cliente no envía (2, 4, 6) cierran la conexión. Un ClientHello con una clave ya conectada reemplaza la conexión anterior, que se cierra. Un SendPacket a una clave no conectada se responde con PeerGone, y uno cuyo datagrama no es WireGuard (`noise.MessageType` distinto de 0) ni disco (magia `mallaDSC`) se descarta sin aviso, porque el relay solo reenvía eso. «Carga reenviada» de `capture_file` es el datagrama sin la clave (u32 big-endian + bytes); el archivo se trunca al arrancar y cada registro se escribe, en una sola escritura, antes de encolar la trama. Cada lado manda KeepAlive cada 30 s y abandona una conexión muda durante 90 s; cada conexión tiene una cola de 1024 tramas y lo que no cabe se descarta, como en UDP. El servidor solo habla HTTP/1.1 (sin h2 por ALPN), para poder secuestrar la conexión, y responde 426 a un GET sin `Connection: Upgrade` y `Upgrade: malla-relay/1`. El certificado vive en `state_dir/relay-cert.pem` y `relay-key.pem`, con el mismo generador que la coordinación (`coord.LoadOrCreateCertFiles`). El cliente se reconecta con espera de 1 s a 10 s. `malla-relay -config relay.json` lee `listen`, `state_dir` y `capture_file` (relativos al archivo; campos desconocidos son error) e imprime `malla-relay: listen <addr> fingerprint <hex>`. La configuración de la coordinación gana el campo `relay`, la URL que anuncia el mapa. En el nodo, el relay del mapa gana sobre `relay_url`, que solo se usa mientras el mapa (o la caché) no anuncia ninguno; sin `relay_fingerprint` el nodo no usa relay, y en modo estático `relay_url` y `relay_fingerprint` son error. En `TestCritRelayHTTPSUDPBlocked` el marcador encabeza cada bloque de 1 KiB de la transferencia; que la transferencia pasó por el relay se comprueba con al menos 4 MiB de mensajes de transporte capturados; «todas las claves que tiene el relay» son el escalar de su clave ECDSA, el SHA-256 de esa clave en PKCS#8, el SHA-256 de su certificado y la clave de ceros, y con cada una se intenta abrir cada mensaje de transporte capturado como ChaCha20-Poly1305 con el nonce del contador.

### 3.3 Disco y hole punching [diseño]

Comparte el socket UDP de WireGuard. Los mensajes WireGuard empiezan con un tipo de 1 a 4 seguido de tres ceros; los de disco empiezan con la magia `"mallaDSC"` (8 bytes), así que la demultiplexación no es ambigua. Trama: magia (8) + clave disco pública del emisor (32) + nonce (24) + XChaCha20-Poly1305 con clave `HKDF(X25519(disco_priv, disco_pub_par), "malla disco v1")`. Cada nodo tiene una clave disco propia, distinta de su clave WireGuard, publicada en el mapa.

Texto plano: `tipo u8`, `versión u8 = 1` y cuerpo.

- `1 Ping`: txid (12) + node_key del emisor (32).
- `2 Pong`: txid (12) + dirección observada del ping (18).
- `3 CallMeMaybe`: n (u8) + n direcciones (18 cada una); viaja por el relay.

Hole punching: al recibir endpoints nuevos de un par o un CallMeMaybe, el nodo manda un CallMeMaybe por el relay y pings a todos los candidatos cada 250 ms durante una ventana de 10 s. Quien recibe un ping responde con un pong a la dirección observada y la agrega como candidato.

**Elección de camino**: un candidato es directo y confirmado si hace menos de 5 s llegó un pong a un ping enviado a él (D23). Se elige el directo confirmado de menor RTT; si no hay ninguno, el relay. Con camino directo, un ping de latido cada 2 s; sin pong en 5 s se vuelve al relay y se reintenta el punching cada 30 s.

**Bind, primera parte** [diseño, k2-02]: `magic.Bind` da a cada par un endpoint ficticio único (`fd6d:616c:6c61::<n>`, puerto 1), que es el único que ve el dispositivo, y traduce en los dos sentidos; así el dispositivo nunca ve una dirección real de un par gestionado y ni su sesión ni su roaming dependen del camino. Un datagrama UDP que llega de un candidato del par (los endpoints del mapa, sin las direcciones de `10.200.0.0/16`, que harían pasar el túnel por sí mismo; el nodo tampoco las reporta) entra al dispositivo con el endpoint ficticio y, si es WireGuard, confirma esa dirección como directa durante 5 s. Uno de una dirección desconocida entra tal cual; si el dispositivo hace roaming del par hacia ella, el runtime se la da al bind como directa confirmada y devuelve el dispositivo al endpoint ficticio. Hasta que exista disco (k2-03) la confirmación es cualquier datagrama WireGuard recibido de esa dirección, antes de autenticarlo. Salida por par: con directa confirmada, solo a ella; si no, con el relay conectado, por el relay, más una copia a cada candidato si es un mensaje de handshake o, si es de transporte, como mucho una por segundo, para notar un directo que empieza a funcionar; sin relay, a la última dirección oída o al primer candidato, y los handshakes a todos. Las copias duplicadas las absorben el timestamp de la iniciación, el índice de la respuesta y la ventana anti-replay. Por el relay solo entra WireGuard de un par conocido. En el modo malla esto reemplaza la regla de k2-01 de cambiar el endpoint del dispositivo solo cuando cambia el del mapa: cada mapa reemplaza los candidatos y la dirección medida se conserva.

**Disco y punching** [diseño, k2-03]: la clave es `HKDF-BLAKE2s(sal vacía, X25519(disco_priv, disco_pub_par), info "malla disco v1")` de 32 bytes; la magia y la clave del emisor van como datos asociados del AEAD y el nonce sale de la fuente aleatoria del bind. Un texto plano cuyo largo no corresponde exactamente a su tipo, o con versión distinta de 1, se descarta. Los datagramas disco, del socket o del relay, van al bind y nunca al dispositivo; el runtime arma su temporizador con el menor vencimiento del dispositivo y del bind. Un ping solo se responde si trae la node_key del par al que el mapa asigna esa clave disco; un pong autenticado con la clave disco del par confirma como directa la dirección a la que se mandó el ping pendiente con su txid, llegue desde donde llegue, y deja medido el RTT; el txid se consume, así que un pong repetido no confirma nada, y un pong que no abre con la clave del par, o cuyo txid no es de un ping pendiente (nunca enviado, ya respondido o descartado por el `Tick` al cumplir 10 s), tampoco (D23, que cambió en p03 la regla original de k2-03: exigía además que el pong llegara desde esa misma dirección). Por el relay solo cuenta CallMeMaybe, y la clave disco del emisor debe ser la del nodo que el relay dice. Con disco (el bind tiene clave y el par tiene clave disco en el mapa) un datagrama WireGuard ya no confirma una dirección nueva, como hacía la regla provisional de k2-02: solo mantiene confirmada la dirección directa vigente; el roaming autenticado por el dispositivo sigue confirmando. Abre una ventana de punching, en el siguiente `Tick`, todo candidato del mapa que el par no tenía (también un par nuevo); un CallMeMaybe recibido con una ventana abierta no la reinicia ni se contesta, para que los dos lados no se manden CallMeMaybe sin fin. Las direcciones de un CallMeMaybe y el origen observado de un ping son candidatos aprendidos: hasta 16 por par (sale el más viejo), nunca una dirección de otro par ni de `10.200.0.0/16`, y se conservan entre mapas. CallMeMaybe lleva los mismos endpoints que el nodo reporta: `magic.Endpoints` pone primero la reflexiva y después las locales con el puerto del socket, sin repetir y hasta 16; el nodo los redescubre cada 30 s y los reporta solo si cambian. El envío simultáneo de pings vive solo en `punchPings` (`internal/magic/punch.go`), para el mutante `mutant_nopunch`.

**Migración**: la sesión WireGuard no depende del camino. Al cambiar de camino, `magic` cambia solo el destino de los paquetes salientes y sigue aceptando entrada por ambos caminos; la ventana anti-replay absorbe el reordenamiento. La migración no reinicia el handshake.

**Elección de camino y migración** [diseño, k2-04]: cada dirección que confirma un pong guarda su propio instante y su RTT, y el bind sale por la confirmada de menor RTT; entre RTT iguales gana la confirmada más reciente, y una dirección confirmada sin RTT medido (roaming, o un datagrama WireGuard de un par sin disco) pierde ante cualquiera medida. Con disco, un datagrama WireGuard ya no mantiene confirmada la dirección vigente, como permitía la regla de k2-03: solo los pongs (y el roaming autenticado) confirman, para que «sin pong en 5 s se vuelve al relay» valga aunque un sentido siga pasando. El latido manda un ping a cada dirección confirmada cada 2 s, el primero 2 s después de la primera confirmación, fuera de una ventana de punching (dentro, los pings salen cada 250 ms). Sin dirección confirmada y sin ventana abierta, se abre una nueva (CallMeMaybe por el relay y pings) 30 s después del inicio de la anterior; tras perder el camino directo se abre enseguida si la última tiene ya 30 s. Además, un datagrama WireGuard que llega de un candidato de un par con disco sin dirección confirmada ni ventana abierta hace que el siguiente `Tick` mande un ping a esa dirección, como mucho uno cada 250 ms: así las copias de sondeo de k2-02 notan un directo que empieza a funcionar sin esperar el reintento. La migración es solo esa elección del destino de salida: `FromUDP` y `FromRelay` aceptan entrada por los dos caminos y el dispositivo no se entera del cambio. En `TestCritMigrationNoCut` la transferencia va a 1 MiB/s (unos 16 s), «el momento del cambio» es la primera salida de `malla status` en A que muestra `direct`, consultada cada 100 ms, y «no reinicia el handshake» se comprueba como ningún evento `handshake` ni `rekey` en los registros de A y B desde que se quita el bloqueo hasta el final.

### 3.4 Línea de comandos [diseño]

- `malla up -config node.json`: arranca el nodo y abre un socket de control Unix en `state_dir/control.sock`.
- `malla status [-json]`: una línea por par: `<nombre> <addr> direct|relay <endpoint>`.
- `malla wait-direct -peer <nombre> -timeout <dur>`: sale con 0 cuando el par tiene camino directo y con 1 si no lo logra en el plazo.

Configuración del nodo (JSON): `private_key_file`, `listen_port`, `coord_url`, `coord_fingerprint`, `auth_key`, `relay_url`, `relay_fingerprint`, `state_dir`, `tun_name`.

**Modo estático** [diseño, k1-06]: sin `coord_url`, `malla up` toma los pares de la configuración: `address` (IP/prefijo del TUN, p. ej. `10.200.0.1/24`) y `peers`, una lista de `{public_key, preshared_key_file, endpoint, allowed_ips, persistent_keepalive}`. Las claves van en base64 estándar como en wg(8) (`public_key` en línea; `private_key_file` y `preshared_key_file` son archivos con la clave en base64, relativos al archivo de configuración si no son absolutos), `endpoint` es `ip:puerto` y es opcional, `allowed_ips` son prefijos y `persistent_keepalive` va en segundos (0 lo apaga). Los campos desconocidos son error, y `coord_url` también hasta que exista la coordinación (K2). El proceso configura el TUN con `ip`: `addr add <address>`, MTU 1420 (el de wg-quick) y `up`, y una ruta `route replace <prefijo> dev <tun>` por cada allowed-IP que no cae dentro del prefijo de `address`. Al quedar listo imprime en la salida estándar `malla: up <tun> <address> listen <puerto> key <pública>`, y en la de errores una línea por evento del dispositivo. El socket de control y `state_dir` llegan con `malla status` (K2). Configuración de la coordinación: `listen`, `stun_listen`, `state_dir`, `admin_token`, `auth_keys`, `policy_file`. Ningún campo requiere datos de César: las pruebas generan claves, tokens y certificados efímeros.

**Modo malla** [diseño, k2-01]: con `coord_url` la configuración del nodo lleva además `name` (obligatorio, el selector de nombre de la política) y `tags` (opcional), `state_dir` es obligatorio, y `address` y `peers` son error. El TUN recibe `<addr>/16`, cuya ruta conectada cubre todos los pares (allowed-IP `addr/32`), y la línea de arranque es la del modo estático con esa dirección. `malla-coord -config coord.json` usa `:3478` si falta `stun_listen`, resuelve `state_dir` y `policy_file` relativos al archivo de configuración e imprime `malla-coord: listen <addr> stun <addr> fingerprint <hex>`. En `TestCritPolicyUnauthorized` C se registra en la coordinación, pero corre un dispositivo simple con B como par estático en vez de seguir su mapa, porque el nodo de malla borraría ese par al aplicar el siguiente mapa.

**Socket de control y CLI** [diseño, k2-04]: solo el modo malla tiene socket de control (el estático no tiene `state_dir`). `mesh.New` abre `state_dir/control.sock` (Unix, flujo, permisos 0600, reemplaza uno viejo), así que existe cuando se imprime la línea `malla: up`. El cliente escribe una línea JSON `{"cmd":"status"}` y el nodo responde una línea `{"peers":[{"name","addr","key","path","endpoint","rtt_ms"}]}` o `{"error":…}`; `malla status -json` imprime ese objeto. `path` es `direct` solo con una dirección confirmada, `relay` con el relay conectado y `none` si no hay ninguno de los dos; `endpoint` es `-` si el camino no es directo, y las líneas van ordenadas por nombre. `status` y `wait-direct` encuentran el socket con `-socket`, o con el `state_dir` de `-config`, o con `$MALLA_SOCKET`. `wait-direct` consulta el estado cada 50 ms; un nodo que aún no responde o no conoce al par cuenta como sin camino directo, y un error de uso sale con 2.

## 4. Matriz teórica de NAT

### 4.1 Modelo [diseño, derivado de RFC 4787 §4.1, §5 y §6]

- Tipos de NAT: mapeo `EIM`, `ADM` o `APDM` × filtrado `EIF`, `ADF` o `APDF` (9 tipos), más `none` (host público, equivale a EIM-EIF sin traducción). Nombre de tipo: `EIM-EIF`, `APDM-APDF`, etc.
- El estado de filtrado se lleva por mapeo (puerto externo): un paquete entrante a un puerto externo pasa según los destinos a los que se envió desde ese mismo mapeo. RFC 4787 lo define por endpoint interno; con EIM ambas lecturas coinciden, y la lectura por mapeo es la que implementa conntrack de Linux, así que el simulador y el NAT real usan la misma.
- Candidatos: cada par conoce el endpoint reflexivo del otro, obtenido del servicio reflexivo del servidor de coordinación, que está en una IP pública distinta de las de los NATs. Las direcciones locales no son enrutables entre los pares. No hay predicción de puertos.
- Protocolo: los dos pares mandan pings simultáneos y repetidos a los candidatos; quien recibe un ping responde con un pong a la dirección observada y la agrega como candidato. Hay conexión directa si los dos pares reciben un pong. Los mapeos siguen activos durante el intento.
- Hairpin: los dos pares están detrás del mismo NAT, en segmentos internos que no se enrutan entre sí salvo a través de la dirección externa del NAT. Si hay hairpin, el NAT presenta el origen externo (REQ-9a).
- CGNAT: NAT doméstico dentro de un NAT de operador en `100.64.0.0/10` (RFC 6598).

### 4.2 Reglas cerradas [hecho: derivadas con un modelo de alcanzabilidad el 2026-10-31; las 185 celdas coinciden con estas reglas]

Sea `E(t)` verdadero si el mapeo de `t` es EIM o `t` es `none`, y `F(t)` su filtrado (`none` cuenta como EIF).

1. **Par de NATs** `a|b`: directo si `E(a)` y `E(b)`. Si exactamente uno es E, por ejemplo `a`: directo si `F(a) ≠ APDF`. Si ninguno es E: directo si (`F(a) = EIF` y `F(b) ≠ APDF`) o (`F(b) = EIF` y `F(a) ≠ APDF`). En otro caso, relay.
2. **Hairpin** `t|hairpin=<bool>`: con hairpin, el resultado es el del par `t|t`; sin hairpin, relay.
3. **Composición CGNAT** `h>c`: un NAT doméstico `h` dentro de un CGNAT `c` equivale a un solo NAT cuyo mapeo y filtrado son los más restrictivos de ambos, con el orden EIM < ADM < APDM y EIF < ADF < APDF.

### 4.3 Archivo `matrix/theory.json` [diseño]

```json
{"format": "malla-nat-theory/1", "source": "RFC 4787",
 "groups": {"pair": {"<a>|<b>": "direct|relay"}, "hairpin": {"<t>|hairpin=True": "…"},
            "cgnat": {"<h>><c>|<b>": "…"}, "cgnat_same": {"<h>><c>|hairpin=True": "…"}}}
```

- `pair`: pares no ordenados de los 10 tipos (orden de la lista `none, EIM-EIF, EIM-ADF, EIM-APDF, ADM-EIF, ADM-ADF, ADM-APDF, APDM-EIF, APDM-ADF, APDM-APDF`, con `a` no posterior a `b`): **55 celdas, 35 directas**.
- `hairpin`: 9 tipos × `hairpin=True|False`: **18 celdas, 5 directas**.
- `cgnat`: `h`, `c` ∈ {EIM-EIF, EIM-ADF, EIM-APDF, APDM-APDF}, `b` ∈ {none} ∪ ese conjunto (el otro par detrás de un solo NAT): **80 celdas, 61 directas**.
- `cgnat_same`: los dos pares, cada uno detrás de su NAT doméstico `h`, detrás del mismo CGNAT `c`, con o sin hairpin en el CGNAT: **32 celdas, 9 directas**.
- Total: 185 celdas.

### 4.4 Qué expresa nftables [hecho: nftables 1.1.7 aceptó y cargó estas reglas el 2026-10-31 dentro de un espacio de usuario; su fidelidad se mide en K3]

| Comportamiento | Regla nftables |
| --- | --- |
| EIM | `snat to <ip>:<puerto>` fijo por endpoint interno |
| APDM | `masquerade fully-random` |
| EIF | mapa dinámico `update @fc { ct reply proto-dst : ct original ip saddr . ct original proto-src }` en postrouting (prioridad srcnat + 1) y `dnat ip to udp dport map @fc` en prerouting |
| ADF | lo mismo, más el conjunto dinámico `@seen { ct reply proto-dst . ip daddr }` que exige `udp dport . ip saddr @seen` |
| APDF | conntrack sin regla de entrada (solo pasan las respuestas) |
| ADM | **no expresable**: nftables no asigna un puerto por IP de destino |

Celdas con oráculo real: las que solo usan `none`, EIM-* y APDM-* (pair 28, hairpin 12, cgnat 80, cgnat_same 32). Las celdas con algún tipo ADM-* son solo del simulador, y la prueba real las enumera en su salida como «sin oráculo real».

**NATs reales, sondeo y matriz real** [diseño, k3-03]: `verify/matrix` arma cada celda con espacios propios (prefijo `m<ranura>`, hasta 4 ranuras en paralelo): un espacio «internet» con la coordinación, el servicio reflexivo y el relay en `198.51.100.1` y los servidores de sondeo en `198.51.100.10–12`, todos en su loopback; cada NAT de primer nivel o host público cuelga de él por su propio /24 de `198.18.0.0/15`, los segmentos internos son `192.168.k.0/24` y los NATs domésticos de un CGNAT están en `100.64.k.0/24`. Cada router tiene una interfaz externa `wan` y las internas `in<k>`. EIM es `snat` a un puerto fijo desde 40000 por endpoint interno conocido (el puerto de malla del host, 51820 para a y 51821 para b, y el de sondeo, +1000; un CGNAT EIM fija además los endpoints que le presenta un doméstico EIM) y `snat` sin puerto para lo demás; APDM es `snat … fully-random` a la dirección externa, equivalente a `masquerade fully-random` pero válido también para el hairpin, que sale por una interfaz interna. El filtrado es el de la tabla, con `@fc` y `@seen` actualizados solo por paquetes de dirección original con snat (y `@seen` también por las respuestas a conexiones entrantes). El router descarta en `input` todo UDP dirigido a él, antes de que conntrack lo confirme, para que un paquete no solicitado no deje una entrada local que choque con un mapeo posterior, y en `forward` todo paquete entre interfaces internas sin dnat. Con hairpin, un datagrama de dentro a la dirección externa se traduce por `@fc` (dnat) y por la cadena de mapeo (snat), y el filtro del mapeo de destino, que necesita el origen ya traducido, se aplica en postrouting tras el snat con `@seenhp` (ADF: puertos externos que enviaron a la dirección externa) y `@seenhpp` (APDF: pares de puertos); conntrack solo no puede expresarlo, porque un paquete atraviesa una sola vez la tabla. El sondeo usa el puerto de sondeo del host: el mapeo es el puerto externo que ven `198.51.100.10:3478` y `198.51.100.11:3479` (igual: EIM; `198.51.100.10:3480` distingue ADM de APDM) y el filtrado, qué llega a lo que vio el primero desde `198.51.100.12` (no contactada), desde `198.51.100.10:3481` y desde `198.51.100.10:3478`. El sondeo de hairpin manda de b al endpoint externo de a y luego de a al de b: llega lo primero solo con hairpin y EIF, lo segundo con hairpin y EIF o EIM, y siempre desde la dirección externa. Las capas CGNAT se miden compuestas (regla 3 de §4.2), desde los hosts, no cada capa por separado. `TestCritNATFidelity` mide así las 12 celdas hairpin y las 32 cgnat_same con oráculo real, y la matriz real sondea los NATs de cada celda antes de levantar la malla. Una celda es `direct` si `malla wait-direct -timeout 30s` sale con 0 en los dos nodos a la vez, como en el simulador, y `relay` si no; sus hallazgos tienen `oracle` = `linux` y `seed` 0.

### 4.5 Archivo de hallazgos `matrix/findings.json` [diseño]

`{"format": "malla-nat-findings/1", "findings": [{"group", "cell", "oracle": "sim"|"linux", "expected", "observed", "kind": "bug"|"hallazgo", "explanation", "seed"}]}`. La prueba de la matriz falla si una celda difiere y no está en el archivo, o si el archivo lista una celda que no difiere. Empieza con `"findings": []`. Desde p03 lista solo los 2 hallazgos de `oracle` = `linux`: los 3 de `oracle` = `sim` que dejó K3 (`pair APDM-EIF|APDM-EIF`, `pair APDM-EIF|APDM-ADF` y `hairpin APDM-EIF|hairpin=True`) venían de la regla de confirmación anterior a D23 y se quitaron con ella.

## 5. Simulador determinista [diseño]

- **Tiempo**: reloj virtual en nanosegundos (`int64`). Cola de eventos ordenada por `(tiempo, secuencia)`; un solo hilo; ninguna llamada al reloj real.
- **Aleatoriedad**: una semilla `uint64` alimenta `math/rand/v2.ChaCha8`, del que salen flujos derivados por nodo y por enlace en orden fijo.
- **Enlaces**: latencia base, jitter uniforme en `[0, jitter]` (que produce reordenamiento) y pérdida Bernoulli `p`.
- **NAT**: el modelo de §4.1 con asignación de puertos determinista, hairpin configurable, anidamiento para CGNAT y timeout de mapeo por inactividad (120 s por defecto, REQ-5; configurable por escenario).
- **Registro de eventos**: JSON Lines con los campos en este orden fijo: `{"t":<ns>,"seq":<n>,"ev":"<tipo>","node":"<id>", …}`. Tipos mínimos: `send`, `deliver`, `drop` (con `reason`: `loss`, `nat_filter`, `no_mapping`, `no_route`), `nat_map`, `nat_expire`, `timer`, `handshake`, `path`.
- **Reproducción**: todo fallo de un verificador basado en el simulador imprime `seed=<n>` y una línea `repro: go test ./<pkg> -run '^<Test>$' -args -sim.seed=<n>` que lo repite.
- **Base del simulador** [diseño, k1-05]: la semilla va en los 8 primeros bytes (little-endian) de la semilla de 32 bytes de ChaCha8, y cada flujo derivado se siembra con los 32 bytes siguientes de ese generador raíz, en orden de creación (`Sim.Stream`: hosts y enlaces al crearse). Un enlace sortea siempre pérdida y retardo, se pierda o no el datagrama, para que los flujos no se desalineen. Las cajas intermedias (`Middlebox`) ven cada datagrama al salir del host, antes de enrutarlo por la dirección de destino, y pueden reescribirlo o descartarlo con un motivo. Además de los tipos mínimos, el registro tiene `inject` y `tun` (paquetes que entran y salen del TUN), `rekey`, `endpoint` y `wg_drop` (eventos del dispositivo; `reason` es el motivo de `internal/device`) y el motivo de descarte `no_port`; los campos opcionales, en este orden, son `src`, `dst`, `len`, `reason` y `peer` (nombre del host del par). `device.Device.Current` describe el keypair actual de un par con índices y resúmenes BLAKE2s de sus claves (`noise.Keypair.KeyIDs`), sin exponerlas, para que una prueba compruebe que los dos extremos comparten la sesión. En el lote de handshakes cruzados cada dispositivo arranca, es decir, abre su puerto, en su instante de arranque con un paquete para el otro, así que los dos inician; lo que llega antes a un puerto cerrado se descarta (`no_port`). `TestCritFailureRepro` corre `go test` en un subproceso con la semilla 11, y `-sim.seed` restringe un lote a esa semilla.
- **Modelo de NAT** [diseño, k3-01]: `Sim.NewNAT(nombre, externa, NATConfig{Mapping, Filtering, Hairpin, Timeout, FirstPort})` crea un NAT de primer nivel y `NAT.NewNAT` uno anidado (el doméstico dentro del CGNAT), cuya dirección externa queda dentro del de fuera; `NAT.Add` pone hosts detrás. Todos los NATs van en una sola `Middlebox`, que primero traduce la salida por el NAT que contiene el origen, del más interno al más externo, y después la entrada por el NAT dueño de la dirección de destino, del más externo al más interno; así el orden no depende del orden de creación. Los enlaces siguen siendo los caminos de extremo a extremo y el NAT solo reescribe. El puerto externo es el siguiente libre desde `FirstPort` (1024 por defecto), en orden y dando la vuelta, sin preservar el puerto interno. Refrescan un mapeo los datagramas salientes y los entrantes aceptados, como conntrack; cada mapeo tiene un solo evento de expiración pendiente que se corre si hubo uso, y al vencer se borra con `nat_expire`. `nat_map` y `nat_expire` llevan `node` = nombre del NAT, `src` = endpoint interno y `dst` = endpoint externo. El estado de filtrado de un mapeo son las direcciones y endpoints a los que envió mientras vive. Sin hairpin, un datagrama de dentro a la dirección externa del propio NAT se descarta con `no_route`; con hairpin se traduce la salida y luego se aplica la entrada, con el filtro del mapeo de destino. Como todo `drop` de una `Middlebox`, `node` es el host que envió. `matrix/theory.json` lo genera `verify/matrix/gentheory` (`go generate ./verify/matrix`), y `TestCritTheoryCoverage` recalcula las reglas de §4.2 con una implementación propia.
- **Malla en el simulador** [diseño, k3-02]: el núcleo sin E/S de un nodo es `mesh.Core` (dispositivo, bind de `magic` y la regla que iguala los pares al mapa, `applyPeers`, que `mesh.Node` comparte); el simulador lo corre con `sim.AttachMesh` y solo transporta mensajes. `sim.Coord` lleva `coord.Core`: registro, reporte de endpoints y long-poll (respuesta al subir la versión o a los 25 s) son llamadas que llegan con la latencia base del enlace nodo–coordinación, sin pérdida y en orden, como sobre TCP; su host atiende el servicio reflexivo en el puerto 3478 por la red simulada, a través de los NATs. `sim.Relay` lleva `relay.Core` y sus tramas, cada conexión un canal confiable y ordenado con la latencia base del enlace nodo–relay. El nodo simulado repite la petición reflexiva cada 1 s hasta tener respuesta (el nodo real se rinde a los 2 intentos y reporta solo las locales) y redescubre cada 30 s; cada cambio de camino de un par se registra como evento `path` (`reason` = `direct`, `relay` o `none`). En la matriz (`verify/matrix`) cada enlace sortea su latencia base en U[10,50] ms, sin jitter; los enlaces UDP pierden con p = 0.01 y los canales del relay no pierden. Una caja intermedia, previa a los NATs, descarta con `no_route` todo datagrama dirigido a una dirección local de un par, así que las locales no se enrutan entre pares ni entre segmentos internos de un mismo NAT. Una corrida es `direct` si los dos nodos informan camino directo al otro en un mismo instante dentro de los 15 s virtuales, y `relay` si no; una celda difiere si alguna semilla da otro resultado que la teoría, y su hallazgo (`oracle` = `sim`) debe tener `expected` = teoría y `observed` = el otro resultado. Con `-sim.seed` solo corre esa semilla, y solo los hallazgos registrados con esa semilla deben seguir difiriendo. En `TestCritSymmetricRelaySim` los dos nodos deben informar `relay` a los 15 s y tras la transferencia, y los 100 datagramas van de a a b cada 10 ms desde los 15 s.
- **Timeout de mapeo** [diseño, k3-02]: el escenario corto de §6 usa dos `internal/device` (a detrás de un NAT EIM-APDF con timeout de 30 s, b público), no la malla, porque en la malla el latido de disco cada 2 s refresca los mapeos de un camino directo y el keepalive persistente no decidiría nada. Con keepalive de 25 s en a ningún mapeo expira y un paquete de b tras 59 s sin datos llega por el mismo endpoint externo; sin keepalive el mapeo expira, ese paquete se descarta con `no_mapping`, y cuando a vuelve a enviar sale por un mapeo nuevo al que b hace roaming y el tráfico se recupera.

## 6. Umbrales numéricos

| Umbral | Valor | Origen |
| --- | --- | --- |
| REKEY_AFTER_TIME, REJECT_AFTER_TIME | 120 s, 180 s | [hecho] kernel v7.2.11 `messages.h` |
| Rekey en recepción (iniciador) | 165 s = REJECT − KEEPALIVE − REKEY_TIMEOUT | [hecho] kernel v7.2.11 `receive.c` |
| REKEY_TIMEOUT, jitter | 5 s, hasta 333 ms (HZ/3) | [hecho] kernel |
| KEEPALIVE_TIMEOUT, REKEY_ATTEMPT_TIME | 10 s, 90 s | [hecho] kernel y wireguard-go |
| REKEY_AFTER_MESSAGES, REJECT_AFTER_MESSAGES | 2^60, 2^64 − 2^13 − 1 | [hecho] kernel y wireguard-go |
| Borrado de claves efímeras | REJECT_AFTER_TIME × 3 | [hecho] kernel `timers.c` |
| Ventana anti-replay | anillo de 8192 bits; ventana útil 8128 | [hecho] kernel `COUNTER_BITS_TOTAL`; wireguard-go `(128−1)·64` |
| Lote de handshakes cruzados | semillas 1..32; latencia U[5,80] ms, jitter U[0,30] ms, pérdida {0, 0.05, 0.2} según `semilla mod 3`, arranques separados U[0,50] ms; plazo 60 s virtuales | [diseño] |
| Matriz en el simulador | semillas 1..8 por celda; latencia U[10,50] ms; pérdida 0.01; directo si se logra en 15 s virtuales | [diseño] |
| Matriz en NATs reales | `wait-direct` de 30 s por celda; hasta 4 celdas en paralelo | [diseño] |
| Migración sin corte | flujo TCP de 16 MiB por el túnel con SHA-256 | [diseño] |
| Cookies bajo carga | 4096 iniciaciones con mac1 válido en menos de 1 s | [diseño]; el kernel entra en carga con 512 en cola (`MAX_QUEUED_INCOMING_HANDSHAKES/8`), wireguard-go con 128 |
| Rekey largo contra el kernel | 200 s con un ping cada 100 ms (2000 pings), 0 perdidos y al menos un handshake nuevo después de 120 s | [diseño] |
| Timeout de mapeo en escenario corto | 30 s con keepalive persistente de 25 s | [diseño] |

## 7. Criterios de la idea → K y prueba

Cada criterio mecánico es una prueba Go `TestCrit<Nombre>`. Una prueba que necesita espacios de red llama a `netns.Require(t)`, que la salta con un mensaje que empieza con `needs-privilege:` si no puede crearlos. `verify/critrun` envuelve `go test -json` y sale con 0 si todo pasa, 77 si lo único no aprobado son saltos `needs-privilege:` y 1 en otro caso. `make check` usa `-short`: las pruebas largas (`TestCritKernelRekeyLong`, `TestCritSimMatrix`, `TestCritLinuxMatrix`) se saltan en modo corto. Los checkers corren sin `-short` y cuentan un salto como fallo.

| # | Criterio | K | Paquete y pruebas |
| --- | --- | --- | --- |
| 1 | Vectores RFC | K1 | `make vectors` sale con 0; `internal/x25519` `TestCritVectorsRFC7748`, `internal/chachapoly` `TestCritVectorsRFC8439`, `internal/blake2s` `TestCritVectorsRFC7693` (Apéndice B y el auto-test del Apéndice E, que cubre la variante con clave), `internal/hkdf` `TestCritVectorsRFC5869` |
| 2 | Wycheproof | K1 | `TestCritWycheproofX25519`, `TestCritWycheproofChaCha20Poly1305`, `TestCritWycheproofXChaCha20Poly1305` sobre archivos copiados sin cambios en `internal/<pkg>/testdata/wycheproof/` |
| 3 | Constantes | K1 | `internal/noise` `TestCritProtocolConstants` |
| 4 | Tamaños | K1 | `internal/noise` `TestCritMessageSizes` (148, 92, 64, 32 + carga cifrada) |
| 5 | Kernel, iniciador propio | K1 | `verify/interop` `TestCritKernelOwnInitiator` |
| 6 | Kernel, respondedor propio | K1 | `verify/interop` `TestCritKernelOwnResponder` |
| 7 | wireguard-go en ambos sentidos | K1 | `verify/interop` `TestCritWireGuardGoOwnInitiator`, `TestCritWireGuardGoOwnResponder` |
| 8 | PSK y cookies | K1 | `verify/interop` `TestCritPSKKernel`, `TestCritPSKWireGuardGo`, `TestCritCookieKernel`, `TestCritCookieWireGuardGo` |
| 9 | Anti-replay | K1 | `internal/noise` `TestCritAntiReplayProperty`; `verify/interop` `TestCritKernelReplay` |
| 10 | Rekey y tiempos | K1 | `internal/device` `TestCritRekeyTimers`; `verify/interop` `TestCritKernelRekeyLong` |
| 11 | Handshakes cruzados | K1 | `verify/props` `TestCritCrossHandshakes` |
| 12 | Roaming | K1 | `internal/device` `TestCritRoaming` |
| 13 | Plano de datos | K1 | `verify/e2e` `TestCritDataplaneAllowedIPs` |
| 25 | Determinismo | K1 | `sim` `TestCritDeterminism` |
| 26 | Reproducción de fallos | K1 | `verify/props` `TestCritFailureRepro` |
| 22 | Políticas | K2 | `verify/e2e` `TestCritPolicyUnauthorized` |
| 23 | Revocación | K2 | `verify/e2e` `TestCritRevocation` |
| 24 | Caída de la coordinación | K2 | `verify/e2e` `TestCritCoordDown` |
| 21 | Relay HTTPS | K2 | `verify/e2e` `TestCritRelayHTTPSUDPBlocked` |
| 19 | Elección de camino y CLI | K2 | `verify/e2e` `TestCritPathCLI` |
| 20 | Migración sin corte | K2 | `verify/e2e` `TestCritMigrationNoCut` |
| 14 | Tabla teórica | K3 | `verify/matrix` `TestCritTheoryCoverage` |
| 15 | Matriz en el simulador | K3 | `verify/matrix` `TestCritSimMatrix` |
| 16 | Matriz en NATs reales | K3 | `verify/matrix` `TestCritLinuxMatrix` |
| 17 | Fidelidad del NAT real | K3 | `verify/matrix` `TestCritNATFidelity` |
| 18 | NAT simétrico | K3 | `verify/matrix` `TestCritSymmetricRelaySim`, `TestCritSymmetricRelayLinux` |
| 27–29 | Mutantes | K3 | `verify/mutants` `TestCritMutantAntiReplay`, `TestCritMutantRekey`, `TestCritMutantHolePunch`; etiquetas de compilación `mutant_noreplay`, `mutant_norekey`, `mutant_nopunch` |
| 30 | Tamaño relativo | K3 | `go run ./verify/cmd/loc` |
| 31 | Costo cero y local | K3 | `go run ./verify/cmd/deps`; compilación con `GOPROXY=off` |
| 32 | Pruebas sin permiso | K3 | `make test-unpriv` (entorno de §8) |
| 33 | No mecánico | — | Sin checker; se declara en `LIMITATIONS.md` |

**Mutantes, conteo, dependencias y suite sin permiso** [diseño, k3-04]: cada mutante es un par de archivos `//go:build <etiqueta>` / `//go:build !<etiqueta>`. `mutant_noreplay` reemplaza `ReplayFilter.ValidateCounter` (`internal/noise/replay_validate.go` ↔ `replay_noreplay.go`) por uno que acepta todo; `mutant_norekey` reemplaza `internal/device/rekey.go` entero (`rekey_norekey.go`): ningún keypair vence por edad y no hay rekey por edad ni por mensajes, pero se conserva el límite REJECT_AFTER_MESSAGES para que el nonce no dé la vuelta; `mutant_nopunch` reemplaza `Bind.sendsPings` (`internal/magic/punch_send.go` ↔ `punch_nopunch.go`), que `ping` consulta, así que el nodo cuya clave pública WireGuard es mayor (comparación de bytes) no manda ningún ping, ni de punching ni de latido ni de sondeo, y solo responde pongs: si solo se cortaran las rondas de `punchPings`, el ping de sondeo de k2-04 que dispara un datagrama WireGuard volvería a abrir el camino en los dos sentidos. Cada prueba de `verify/mutants` corre, desde la raíz del módulo, `go test -tags <etiqueta> -json -count=1 -timeout <plazo> -run '^<Prueba>$' <paquete>` y pasa solo si la prueba de nivel superior corrió y falló y su salida (con la de sus subpruebas) contiene la frase de la propiedad; en `TestCritMutantHolePunch` además alguna línea `<grupo> <celda>: theory direct, observed relay` debe nombrar una celda que `matrix/theory.json` da como directa. `TestCritMutantHolePunch` corre la matriz simulada completa, así que, como `TestCritSimMatrix`, se salta con `-short`. `verify/cmd/loc` decide qué es código con el escáner de `go/scanner` (los marcadores de comentario dentro de cadenas no cuentan como comentario y cada línea no vacía de un token de varias líneas cuenta), cuenta todos los `.go` de las rutas de §2.3, `testdata` incluido, imprime `product <n>`, `support <n>`, `product-tests <n>` y `support/product <p>%` con la referencia del 15 %, y sale con 1 si apoyo ≥ producto y con 2 si no puede leer. `verify/cmd/deps` toma el módulo de cada paquete no estándar de `go list -deps -test -json ./...` (para la plataforma de la máquina), el directorio del reemplazo si lo hay, y como archivo de licencia el de nombre más corto que empieza con `LICENSE`, `LICENCE` o `COPYING` en la raíz del módulo; lo clasifica por frases del texto canónico, sin mayúsculas ni cortes de línea, y un módulo sin archivo de licencia cuenta como no reconocido. «SDK de una API de pago» es un prefijo de una lista fija (Anthropic, OpenAI, Gemini, Google Cloud, AWS, Azure, Cohere, Mistral, Stripe, Twilio). `make test-unpriv` pone `GOFLAGS` y `GOPROXY` con `env` dentro de `setpriv`, en el entorno de §8.

Las pruebas con espacios de red no usan sudo: el arnés `verify/netns` se re-ejecuta en un espacio de usuario y de red nuevo (`CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS` con mapeo de uid a root), monta un tmpfs en `/run`, crea los espacios con `ip netns add` y los configura con `ip` y `nft`. El enlace wireguard del kernel se configura con `wgctrl` (netlink), porque `wg` no está instalado.

## 8. Entorno sin permiso [hecho: probado el 2026-10-31]

```
unshare -rU sh -c 'echo 0 > /proc/sys/user/max_user_namespaces; exec setpriv --securebits +noroot,+noroot_locked,+no_setuid_fixup,+no_setuid_fixup_locked --bounding-set -all --inh-caps -all --ambient-caps -all -- <comando>'
```

Dentro, `unshare -n` falla con «Operation not permitted» y `unshare -rUn` con «No space left on device»: no hay espacios de red ni de usuario. `make test-unpriv` corre la suite completa así, con `GOFLAGS=-mod=mod GOPROXY=off`.

## 9. Decisiones cerradas

Las D01–D16 son la lista `decisiones_delegadas_al_k0` de la idea, en su orden; las D17 en adelante las abrió el diseño.

**D01 · Lenguaje.**
Decisión: Go 1.27 (toolchain local go1.27.3).
Razón: medido el 2026-10-31: wireguard-go (oráculo) y `wgctrl` (configuración del kernel por netlink) son bibliotecas Go que corren dentro del proceso de prueba; `wgctrl` configuró un enlace wireguard del kernel dentro de un espacio de usuario sin sudo, y wireguard-go trae un TUN en memoria (`tun/netstack`). En Rust no hay oráculo dentro del proceso, haría falta un proceso aparte con TUN. La compilación en frío de Go fue de 2.45 s (hola mundo) y 3.48 s (con wgctrl), sin efecto en la decisión.

**D02 · Arquitectura y tamaño del apoyo.**
Decisión: la de §2: núcleos sans-IO compartidos por el runtime real y el simulador; conteo de §2.3.
Razón: el simulador no duplica el protocolo, así que su tamaño es el de un planificador más modelos de NAT, y el conteo separa producto y apoyo por ruta, sin juicio manual.

**D03 · Matriz teórica y nftables.**
Decisión: §4: 185 celdas que siguen tres reglas cerradas más la composición CGNAT; real en las celdas sin ADM.
Razón: un modelo de alcanzabilidad sobre las definiciones de RFC 4787 produjo la tabla, y las reglas la reproducen sin excepciones; nftables 1.1.7 cargó las reglas de EIM, APDM, EIF, ADF y APDF, y no tiene forma de expresar ADM.

**D04 · Simulador.**
Decisión: §5: eventos discretos con reloj virtual en ns, ChaCha8 con semilla, enlaces con latencia, jitter y pérdida, NAT con timeouts, registro JSON Lines con orden de campos fijo.
Razón: un solo hilo y una sola fuente de aleatoriedad hacen que la misma semilla dé el mismo registro byte a byte.

**D05 · Orden de fases.**
Decisión: K1 protocolo, criptografía, simulador base e interoperabilidad; K2 malla (coordinación, relay, traversal, CLI); K3 matriz de NAT, mutantes y criterios globales.
Razón: cada K se apoya en el anterior y cierra con pruebas propias; la matriz necesita la malla completa y los mutantes rompen código de K1 y K2.

**D06 · Umbrales.**
Decisión: la tabla de §6.
Razón: las constantes de WireGuard salen del kernel v7.2.11; los demás valores son los mínimos que hacen cada prueba decidible en una máquina de 16 GB sin pruebas de horas.

**D07 · Ventana anti-replay y roaming.**
Decisión: anillo de 8192 bits con ventana útil de 8128 contadores; el endpoint de un par solo cambia tras una iniciación o respuesta válidas o tras un paquete de datos que pasa el AEAD y la ventana.
Razón: el kernel v7.2.11 define `COUNTER_BITS_TOTAL = 8192` y ventana `8192 − BITS_PER_LONG`, wireguard-go usa `(128−1)·64 = 8128`, y el kernel llama a `wg_socket_set_peer_endpoint` solo en esos tres puntos de `receive.c`. Los 2048 bits de meshguard no coinciden con el kernel.

**D08 · Espacios de usuario sin privilegios.**
Decisión: sirven y no hace falta sudo; las pruebas privilegiadas devuelven 77 solo si no se pueden crear.
Razón: medido el 2026-10-31 en Arch (kernel 7.2.11, `unprivileged_userns_clone = 1`): dentro de `unshare -rUmn` se crearon veth, varios espacios de red, reglas NAT de nftables, TUN y el enlace `wireguard` del kernel.

**D09 · wireguard-go.**
Decisión: se usa como biblioteca dentro del proceso de prueba con `tun/netstack` y `conn.NewDefaultBind`, sin sudo, fijado en `golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee` con `go.sum`.
Razón: no está instalado como binario; como módulo Go queda fijado por hash y, con la caché de módulos poblada, compila sin red.

**D10 · tailscaled con Headscale.**
Decisión: no se usa como oráculo.
Razón: ninguno de los dos está instalado, ningún criterio lo exige, y la matriz ya tiene dos jueces (teoría y NATs reales) más el simulador.

**D11 · Vectores y hallazgos.**
Decisión: Wycheproof se copia sin cambios del commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` (`x25519_test.json`, `chacha20_poly1305_test.json`, `xchacha20_poly1305_test.json`), con los SHA-256 de `vault/RESEARCH.md`; los vectores RFC se transcriben a `testdata/rfcNNNN.json`; no hay vectores públicos de handshake completo, así que los oráculos (kernel y wireguard-go) hacen de vector; hallazgos con el formato de §4.5.
Razón: las copias quedan verificables por hash y las pruebas corren sin red.

**D12 · Protocolos propios.**
Decisión: coordinación HTTPS+JSON, servicio reflexivo UDP, disco y relay HTTPS con tramas propias, como en §3.
Razón: no hay especificación pública verificada de disco ni de DERP; un formato propio mínimo y documentado se puede verificar de punta a punta.

**D13 · Políticas.**
Decisión: grupos, tags y reglas simétricas con denegación por defecto; revocación que saca al nodo de todos los mapas, invalida su token y bloquea su clave.
Razón: es el mínimo que satisface los criterios 22 y 23; las reglas direccionales exigirían filtrado con estado, que ningún criterio pide.

**D14 · Herramientas de medición.**
Decisión: conteo de líneas propio en Go (`verify/cmd/loc`), contrastado por el checker con cloc 2.10; captura de paquetes por la opción `capture_file` del relay y por sockets propios de la prueba, sin tcpdump (no está instalado); contadores del kernel leídos de `/sys/class/net/<dev>/statistics` y de `wgctrl`; reloj simulado = reloj virtual de `sim`.
Razón: todo está en la máquina o en la biblioteca estándar, y los checkers leen salidas crudas.

**D15 · Vacante de Networking (Dataplane).**
Decisión: queda registrada como abierta y sin evidencia de que admita candidatos desde México.
Razón: la API pública de Greenhouse de Tailscale (consultada el 2026-10-31) lista «Software Engineer, Networking (Dataplane)» como Remote (United States), id 4732897005, y como Remote (Canada), id 4732874005, ambas actualizadas el 2026-09-29; el id 4703138005 de la investigación devuelve 404, y el texto de las dos vacantes no menciona México.

**D16 · Predicción de puertos.**
Decisión: no se intenta.
Razón: está fuera del alcance elegido, y el único oráculo local para NAT simétrico (`fully-random`) asigna puertos al azar, así que no hay comportamiento predecible que medir.

**D17 · Criptografía de los canales de control.**
Decisión: coordinación y relay usan `crypto/tls` de Go; WireGuard y disco usan solo las primitivas propias.
Razón: la idea exige primitivas propias para WireGuard; el relay solo ve ciphertext WireGuard, así que su TLS no protege los datos de la malla.

**D18 · Prefijo de la malla.**
Decisión: direcciones de la malla en `10.200.0.0/16`.
Razón: `100.64.0.0/10` (el de Tailscale) choca con el segmento CGNAT de las pruebas.

**D19 · Licencia y visibilidad.**
Decisión: MIT, suponiendo que el repositorio será público.
Razón: es un proyecto para mostrar; la licencia de wireguard-go también es MIT. Publicarlo o no lo decide César.

**D20 · CI.**
Decisión: el CI corre `make check`, el mismo comando de chequeo.
Razón: los formatos de kiln exigen que el CI corra el comando de chequeo; `make check` corre los tests más formato y vet, que son baratos.

**D21 · Interoperabilidad sin herramienta `wg`.**
Decisión: el kernel se configura con `golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10`.
Razón: `wireguard-tools` no está instalado y `wgctrl` funcionó dentro de un espacio de usuario.

**D22 · Exactitud de las primitivas en tiempo constante.**
Decisión: X25519 con escalera de Montgomery y aritmética de campo sin ramas que dependan de secretos; las comparaciones de etiquetas, con `crypto/subtle`.
Razón: las primitivas son propias; tiempo constante es parte de implementarlas bien, aunque el proyecto no reclama resistencia auditada (ver `LIMITATIONS.md`).

**D23 · Qué dirección confirma un pong** (p03).
Decisión: un pong autenticado con la clave disco del par confirma como directa la dirección a la que se mandó el ping pendiente con su txid, aunque el pong llegue desde otro origen; ya no se exige que llegue desde esa dirección, como pedía k2-03.
Razón: el modelo de §4.1 da directo si los dos pares reciben un pong, y detrás de un APDM del simulador el pong sale por un mapeo nuevo, así que con la regla de k2-03 tres celdas que la teoría da como directas quedaban en relay con las 8 semillas; confirmar el destino del ping las hace coincidir (medido una vez en el fix de k3 y revertido entonces). No abre un camino sin autenticar: el pong sigue cifrado con la clave disco del par, su txid de 12 bytes aleatorios solo viajó dentro de un ping cifrado a esa dirección, solo cuenta si es de un ping pendiente y se consume al primer uso; un datagrama que no cumple eso no confirma nada. Lo que prueba es que el ping llegó al par por esa dirección; el origen del pong no prueba nada más y por eso no se mira.

## 10. Contradicciones resueltas

- **Clave de 128 bits del MAC.** La idea y la investigación hablan de «BLAKE2s con clave de 128 bits para MAC». La página del protocolo define `MAC(key, input) = Keyed-Blake2s(key, input, 16)`: la salida es de 16 bytes. La clave es de 32 bytes en mac1 y de 16 bytes en mac2 (la cookie). Se implementa BLAKE2s con clave de 1 a 32 bytes y salida de 1 a 32 bytes, y se prueban ambos usos.
- **Rekey en recepción.** La página del protocolo dice `REKEY_AFTER_TIME − KEEPALIVE_TIMEOUT − REKEY_TIMEOUT` (105 s); el kernel v7.2.11 usa `REJECT_AFTER_TIME − KEEPALIVE_TIMEOUT − REKEY_TIMEOUT` (165 s), que es lo que dice la idea. Gana el kernel, porque es el oráculo.
- **Sudo.** La idea permite sudo; las mediciones de D08 muestran que no hace falta. Las pruebas no usan sudo.
- **CI.** El método dice que el CI corre solo los tests; los formatos de kiln dicen que corre el comando de chequeo. Gana kiln (D20).
- **Tests y conteo de líneas.** La idea pide «simulador más verificadores < malla»; las pruebas unitarias del producto no cuentan en ningún lado (§2.3) y se informan aparte para no esconderlas.
