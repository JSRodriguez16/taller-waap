# Matriz de Resultados - Fase 6

| Payload / técnica | Bloqueado por reglas (Fase 2) | Detectado por IA/ML (Fase 3) | Bloqueado por RASP (Fase 4) | Score IA |
| :--- | :---: | :---: | :---: | :---: |
| SQLi clásico ' OR '1'='1            | Sí                             | Sí                           | Sí                          | -0.051   |
| SQLi con codificación URL           | No                             | Sí                           | Sí                          | -0.0515  |
| SQLi fragmentado en 2 parámetros    | No                             | Sí                           | Sí                          | -0.0523  |
| XSS reflejado básico                | Sí                             | Sí                           | Sí                          | -0.0463  |
| Ráfaga de peticiones (bot)          | No                             | Sí                           | N/A                         | -0.004   |
