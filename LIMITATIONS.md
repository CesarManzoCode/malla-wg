# Límites

Esta es la fuente única de los límites de malla-wg: lo que el proyecto no demuestra.

- **Criptografía sin auditoría.** Las primitivas (X25519, ChaCha20-Poly1305, XChaCha20-Poly1305, BLAKE2s, HKDF) son propias y existen para este proyecto de verificación. Pasar los vectores RFC y Wycheproof no prueba que resistan canales laterales ni que estén listas para producción.
- **Sin internet real.** La matriz de NAT vale para NATs de Linux (nftables) y para el simulador; no dice nada de routers de consumo, CGNAT de operadores, redes móviles ni de la tasa de conexiones directas de una población real.
- **ADM sin oráculo real.** nftables no puede expresar el mapeo dependiente de la dirección; esas celdas solo se miden en el simulador.
- **Modelo de filtrado por mapeo.** La tabla teórica supone que el filtrado se evalúa por puerto externo, como conntrack de Linux. RFC 4787 lo define por endpoint interno; un NAT que siga la otra lectura puede dar resultados distintos en celdas sin EIM.
- **Fuera de alcance.** Predicción de puertos para NAT simétrico (paradoja del cumpleaños), IPv6 y traducción de prefijos, aceleración de rendimiento al nivel del kernel.
- **Relay sin autenticación de clave.** El relay acepta la clave de nodo que declara el cliente. Un cliente malicioso podría recibir el tráfico relayado de otro nodo: solo ciphertext WireGuard, así que afecta la disponibilidad, no la confidencialidad.
- **Políticas mínimas.** Reglas simétricas entre nodos, tags y grupos; no hay reglas por puerto ni direccionales.
- **Dificultad no medida.** La afirmación de que este proyecto es más difícil que los anteriores no tiene criterio automático; solo la sostienen las mediciones de los demás criterios.
- **Cookies bajo carga dependen del oráculo y de la CPU.** `TestCritCookieKernel` y `TestCritCookieWireGuardGo` solo prueban la cookie si la inundación pone al oráculo bajo carga, y eso lo decide el largo de su cola de handshakes, no la prueba; la prueba lo comprueba por las respuestas de cookie a la inundación y la repite hasta 10 veces si no lo logró. Medido el 2026-10-31 en esta máquina (12 CPU): sin otra carga, cada inundación puso bajo carga al kernel y a wireguard-go al primer intento; compilando en paralelo (`go build -a std` sin caché), wireguard-go siguió entrando al primer intento, pero el kernel necesitó de 3 a 5 intentos, porque sus trabajadores de handshake drenan la cola más rápido de lo que llegan los datagramas. Con más contención que esa la prueba puede fallar sin que el nodo propio haya hecho nada mal.
