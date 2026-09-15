# Plataforma WAAP (Web Application and API Protection) con IA/ML, RASP y DevSecOps

## Descripción del Proyecto

Este repositorio contiene la implementación integral de una plataforma **WAAP (Web Application and API Protection)** de nueva generación, combinando:
1. **Motor de Reglas Perimetral (Core Rule Engine)** basado en OWASP CRS / Coraza.
2. **Módulo de Inteligencia Artificial / Machine Learning (IA/ML)** no supervisado con *Isolation Forest* para detección de anomalías y bots volumétricos.
3. **Agente RASP (Runtime Application Self-Protection)** embebido para inspección contextual en tiempo de ejecución (prevención de SQLi fragmentado y bypasses de decodificación).
4. **Pipeline DevSecOps** automatizado en GitHub Actions con puertas de calidad de seguridad: SAST (*Semgrep*), SCA (*pip-audit*), Container Scanning (*Trivy*), IaC Scanning (*Checkov*), DAST (*OWASP ZAP*) y despliegue como código (*Policy as Code*).
5. **Observabilidad Centralizada y Métricas** de rendimiento, latencia (overhead) y MTTD (*Mean Time to Detect*).

---

## Estructura del Repositorio

```text
taller-waap/
├── app/
│   ├── app.py                     # Aplicación web Flask vulnerable objetivo
│   ├── rasp_agent.py              # Agente RASP (decorador de inspección runtime)
│   ├── requirements.txt           # Dependencias validadas para SCA
│   └── Dockerfile                 # Contenedor hardened sin privilegios root
├── waap/
│   ├── coraza/
│   │   └── coraza.conf            # Configuración de reglas WAF SecLang y Paranoia PL1-PL4
│   ├── ml/
│   │   ├── extract_features.py    # Extracción de características (entropía Shannon, RPM, regex)
│   │   ├── generate_traffic.py    # Generador de tráfico normal y dataset sintético
│   │   ├── train_model.py         # Entrenamiento del modelo Isolation Forest
│   │   ├── score_request.py       # Inferencia y evaluación de anomalía
│   │   └── model.pkl              # Modelo binario entrenado
│   └── orchestrator.py            # Orquestador de Decisión Multi-Capa (Reglas + IA + RASP)
├── .github/
│   └── workflows/
│       └── devsecops.yml          # Pipeline CI/CD DevSecOps para GitHub Actions
├── pipeline/
│   └── .github/workflows/
│       └── devsecops.yml          # Réplica de referencia del workflow CI/CD
├── scripts/
│   ├── deploy_waap_rules.sh       # Script de despliegue automatizado de reglas WAAP
│   ├── run_attack_matrix.py       # Ejecución de la Matriz de Pruebas Fase 6
│   ├── benchmark_rasp_latency.py  # Benchmark comparativo de latencia con/sin RASP
│   └── calculate_metrics.py       # Cálculo de métricas de seguridad y MTTD (Fase 7)
├── logs/
│   ├── access.log                 # Registro estructurado de peticiones HTTP
│   ├── features_normal_traffic.csv# Dataset de entrenamiento de tráfico normal
│   ├── matriz_fase_6.md           # Resultados de la matriz comparativa de ataque
│   ├── latencia_rasp_benchmark.md # Resultados de benchmarking de latencia
│   └── metricas_fase_7.md         # Panel de métricas y tuning
├── docker-compose.yml             # Orquestación de Juice Shop, RASP App y ModSecurity Proxy
├── INFORME_TALLER_WAAP.md         # Informe Técnico completo y Cuestionario resuelto
└── README.md
```

---

### Prerrequisitos
- **Python 3.10+** (recomendado Python 3.11 con `scikit-learn`, `pandas`, `flask`, `requests`, `joblib`).
- **Docker y Docker Compose** (para levantar OWASP Juice Shop y el Proxy ModSecurity CRS).

### 1. Levantar la Infraestructura (Fase 0)
```bash
docker compose up -d
docker compose ps
```
- **Juice Shop objetivo:** `http://localhost:3000`
- **Proxy WAAP (ModSecurity CRS):** `http://localhost:8080`
- **App vulnerable con RASP:** `http://localhost:5000`

---

## Ejecución de Scripts y Fases del Taller

### Fase 3 — Módulo IA/ML (Entrenamiento e Inferencia)
1. **Generar dataset y reentrenar modelo Isolation Forest:**
   ```bash
   python waap/ml/train_model.py
   ```
2. **Ejecutar evaluación de 10 peticiones (5 benignas vs 5 maliciosas):**
   ```bash
   python waap/ml/score_request.py --benchmark
   ```

### Fase 4 — Agente RASP y Medición de Latencia
1. **Medir impacto de latencia con y sin RASP (mínimo 20 peticiones):**
   ```bash
   python scripts/benchmark_rasp_latency.py
   ```

### Fase 6 — Matriz Comparativa de Ataque y Evasión
1. **Ejecutar los 5 escenarios de ataque contra las 3 capas (Reglas, IA/ML, RASP):**
   ```bash
   python scripts/run_attack_matrix.py
   ```

### Fase 7 — Observabilidad, Métricas y MTTD
1. **Calcular métricas globales (TP, FN, FP, Recall, Precisión, MTTD):**
   ```bash
   python scripts/calculate_metrics.py
   ```

### Orquestador de Decisión Integrado
1. **Probar el flujo completo de decisión (ALLOW, BLOCK, CHALLENGE):**
   ```bash
   python waap/orchestrator.py
   ```