# waap/ml/score_request.py — Inferencia y cálculo de anomalía sobre peticiones HTTP entrantes
# Taller WAAP: Fase 3.4 - Inferencia e integración con el orquestador de decisión

import os
import sys
import argparse
import joblib
import pandas as pd
from typing import Dict, Any

# Importar extractor de características
sys.path.append(os.path.dirname(__file__))
from extract_features import extract

def _get_model_path():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    return os.path.join(base_dir, 'waap', 'ml', 'model.pkl')

# Carga perezosa (lazy) del bundle de modelo
_BUNDLE = None

def get_bundle():
    global _BUNDLE
    if _BUNDLE is None:
        path = _get_model_path()
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            raise FileNotFoundError(f"El modelo no ha sido entrenado aún en: {path}. Ejecute train_model.py primero.")
        _BUNDLE = joblib.load(path)
    return _BUNDLE

ANOMALY_THRESHOLD = -0.05

def score(features: Dict[str, Any]) -> float:
    """
    Calcula el score de decisión con Isolation Forest.
    Valores negativos (< 0) indican mayor probabilidad de anomalía/ataque.
    """
    bundle = get_bundle()
    model, scaler = bundle['model'], bundle['scaler']
    feature_cols = bundle.get('features', ['url_length', 'body_length', 'entropy', 'n_params', 'has_suspicious_chars', 'req_per_minute'])

    # Asegurar orden y tipos de columnas
    df_feat = pd.DataFrame([{col: float(features.get(col, 0.0)) for col in feature_cols}])
    X_scaled = scaler.transform(df_feat)
    return float(model.decision_function(X_scaled)[0])

def is_anomalous(features: Dict[str, Any], threshold: float = ANOMALY_THRESHOLD) -> bool:
    """Determina si la petición es anómala según el umbral configurado."""
    return score(features) < threshold

def evaluate_request(url: str, body: str = '', req_per_minute: float = 1.0, threshold: float = ANOMALY_THRESHOLD) -> Dict[str, Any]:
    """Evalúa una petición HTTP completa calculando características, score y clasificación."""
    req_row = {'url': url, 'body': body, 'req_per_minute': req_per_minute}
    feats = extract(req_row)
    anomaly_score = score(feats)
    anomalous = anomaly_score < threshold
    return {
        "url": url,
        "features": feats,
        "score": round(anomaly_score, 4),
        "threshold": threshold,
        "is_anomalous": anomalous,
        "verdict": "ANOMALOUS (ATAQUE/BOT)" if anomalous else "BENIGN (NORMAL)"
    }

def run_phase_3_benchmark():
    """Ejecuta las 10 peticiones requeridas por el Entregable de la Fase 3 (5 normales y 5 maliciosas/evasión)."""
    print("=" * 80)
    print("  EVALUACIÓN FASE 3: MATRIZ DE 10 PETICIONES (5 NORMALES VS 5 MALICIOSAS)")
    print(f"  Umbral configurado (ANOMALY_THRESHOLD): {ANOMALY_THRESHOLD}")
    print("=" * 80)

    test_cases = [
        # 5 Peticiones Normales
        {"category": "Normal 1", "url": "http://localhost:8080/", "body": "", "rpm": 5},
        {"category": "Normal 2", "url": "http://localhost:8080/rest/products/search?q=apple", "body": "", "rpm": 12},
        {"category": "Normal 3", "url": "http://localhost:8080/rest/products/12", "body": "", "rpm": 8},
        {"category": "Normal 4", "url": "http://localhost:8080/rest/user/login", "body": '{"email":"customer@udistrital.edu.co","password":"Password123"}', "rpm": 4},
        {"category": "Normal 5", "url": "http://localhost:8080/assets/public/favicon_js.ico", "body": "", "rpm": 2},

        # 5 Peticiones de Ataque / Evasión
        {"category": "SQLi Clásico", "url": "http://localhost:8080/rest/products/search?q=' OR '1'='1", "body": "", "rpm": 5},
        {"category": "SQLi URL Encoded", "url": "http://localhost:8080/rest/products/search?q=%27%20OR%20%271%27%3D%271", "body": "", "rpm": 5},
        {"category": "SQLi Fragmentado", "url": "http://localhost:8080/login?username=' OR '&password=1=1 --", "body": "", "rpm": 5},
        {"category": "XSS Reflejado", "url": "http://localhost:8080/rest/products/search?q=<script>alert(1)</script>", "body": "", "rpm": 5},
        {"category": "Bot / Ráfaga", "url": "http://localhost:8080/rest/products/search?q=test", "body": "", "rpm": 450} # alta frecuencia por minuto
    ]

    results = []
    print(f"{'Categoría':<20} | {'Score':<8} | {'¿Anómalo?':<10} | {'URL / Payload'}")
    print("-" * 80)
    for tc in test_cases:
        eval_res = evaluate_request(tc['url'], tc['body'], tc['rpm'])
        results.append({**tc, **eval_res})
        print(f"{tc['category']:<20} | {eval_res['score']:<8.4f} | {str(eval_res['is_anomalous']):<10} | {tc['url'][:45]}")

    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Evaluar anomalía de petición HTTP con IA/ML")
    parser.add_argument("--url", type=str, help="URL de la petición a evaluar")
    parser.add_argument("--body", type=str, default="", help="Cuerpo de la petición HTTP")
    parser.add_argument("--rpm", type=float, default=1.0, help="Peticiones por minuto (req_per_minute)")
    parser.add_argument("--benchmark", action="store_true", help="Ejecutar benchmark de 10 peticiones para Fase 3")
    
    args = parser.parse_args()

    if args.benchmark or (not args.url):
        run_phase_3_benchmark()
    else:
        res = evaluate_request(args.url, args.body, args.rpm)
        print("\n--- Resultado de Inferencia WAAP IA/ML ---")
        print(f"URL: {res['url']}")
        print(f"Características extraídas: {res['features']}")
        print(f"Score de anomalía: {res['score']}")
        print(f"Veredicto: {res['verdict']}")