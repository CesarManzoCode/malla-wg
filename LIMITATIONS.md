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
