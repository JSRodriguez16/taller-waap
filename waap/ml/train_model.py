# waap/ml/train_model.py — Entrenamiento del modelo de detección de anomalías
# Taller WAAP: Fase 3.3 - Entrenamiento del modelo (Isolation Forest)

import os
import sys
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

def get_paths():
    # Resolver rutas relativas tanto si se ejecuta desde raíz como desde waap/ml
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    csv_path = os.path.join(base_dir, 'logs', 'features_normal_traffic.csv')
    model_path = os.path.join(base_dir, 'waap', 'ml', 'model.pkl')
    return base_dir, csv_path, model_path

def train():
    base_dir, csv_path, model_path = get_paths()

    # Si no existe el CSV, generarlo usando generate_traffic
    if not os.path.exists(csv_path):
        print(f"[*] Archivo {csv_path} no encontrado. Generando tráfico normal...")
        sys.path.append(os.path.dirname(__file__))
        from generate_traffic import generate_normal_dataset
        generate_normal_dataset(num_samples=1200, output_csv=csv_path)

    print(f"[*] Cargando dataset de tráfico normal desde: {csv_path}")
    df = pd.read_csv(csv_path)
    
    feature_cols = ['url_length', 'body_length', 'entropy', 'n_params', 'has_suspicious_chars', 'req_per_minute']
    X = df[feature_cols].astype(float)

    print(f"[*] Ajustando StandardScaler sobre {len(X)} muestras...")
    scaler = StandardScaler().fit(X)
    X_scaled = scaler.transform(X)

    print("[*] Entrenando Isolation Forest (n_estimators=200, contamination=0.02, random_state=42)...")
    model = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    ).fit(X_scaled)

    # Evaluar puntuaciones de anomalía sobre datos normales
    normal_scores = model.decision_function(X_scaled)
    print(f"[+] Estadísticas de score en tráfico normal:")
    print(f"    Media: {normal_scores.mean():.4f}")
    print(f"    Mínimo: {normal_scores.min():.4f}")
    print(f"    Máximo: {normal_scores.max():.4f}")
    print(f"    Percentil 5%: {pd.Series(normal_scores).quantile(0.05):.4f}")

    # Guardar modelo y scaler
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump({'model': model, 'scaler': scaler, 'features': feature_cols}, model_path)
    print(f"[+] Modelo entrenado y guardado exitosamente en: {model_path} ({os.path.getsize(model_path)} bytes)")

if __name__ == '__main__':
    train()