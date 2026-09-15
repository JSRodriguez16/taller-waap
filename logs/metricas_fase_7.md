# Panel de Métricas de Seguridad y Observabilidad - Fase 7

| Capa de Seguridad | TP | FN | FP | Detección (Recall) | Precisión | Falsos Positivos | MTTD Estimado |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Motor de Reglas (CRS PL1)             | 2  | 3  | 0  | 40.0%              | 100.0%    | 0.0%             | 1.250 ms      |
| Módulo IA/ML (Isolation Forest)       | 5  | 0  | 2  | 100.0%             | 71.4%     | 2.0%             | 3.820 ms      |
| Agente RASP (Runtime SQL/Code)        | 4  | 0  | 0  | 100.0%             | 100.0%    | 0.0%             | 0.007 ms      |
| Defensa en Profundidad (WAAP + RASP)  | 5  | 0  | 0  | 100.0%             | 100.0%    | 0.0%             | 4.150 ms      |


### Recomendaciones de Ajuste de Umbrales (Tuning):
1. **Reglas (Paranoia Level)**: Mantener CRS en PL1 para el tráfico general con el fin de evitar falsos positivos en APIs con JSON extenso. Para endpoints críticos como `/rest/user/login`, elevar a PL2 o aplicar reglas virtuales específicas.
2. **IA/ML (Umbral de anomalía)**: 
   - Configurar `ANOMALY_THRESHOLD = -0.04` para bloqueo directo.
   - Peticiones con `-0.04 <= Score < 0.00` no deben ser bloqueadas inmediatamente, sino enviadas a un **Challenge (desafío CAPTCHA / Rate-Limit)** para reducir a 0% los falsos positivos en clientes legítimos.
3. **RASP**: Excelente relación costo-beneficio con latencia imperceptible (~0.007 ms). Debe mantenerse activo en operaciones de base de datos críticas para actuar como red de seguridad definitiva (Zero-Bypass).
