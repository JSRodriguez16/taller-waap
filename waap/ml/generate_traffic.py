# waap/ml/generate_traffic.py — Generador de tráfico normal y dataset para entrenamiento de IA/ML
# Taller WAAP: Fase 3.1 - Recolección y etiquetado del tráfico

import os
import random
import time
import json
import pandas as pd
from datetime import datetime
from extract_features import extract

# Asegurar directorios
os.makedirs("logs", exist_ok=True)

NORMAL_SEARCH_TERMS = [
    "apple", "orange", "juice", "banana", "smoothie", "organic", "water", 
    "glass", "mug", "shirt", "strawberry", "lemon", "honey", "bottle",
    "delivery", "gift", "box", "pack", "discount", "fresh"
]

NORMAL_PATHS = [
    ("/", "GET", None),
    ("/rest/products/search?q={term}", "GET", None),
    ("/rest/products/{id}", "GET", None),
    ("/api/Feedbacks/", "GET", None),
    ("/api/BasketItems/", "GET", None),
    ("/rest/user/login", "POST", "LOGIN_BODY"),
    ("/rest/basket/{id}", "GET", None),
    ("/api/Quantitys/{id}", "GET", None),
    ("/assets/public/favicon_js.ico", "GET", None),
    ("/main.js", "GET", None),
    ("/styles.css", "GET", None)
]

def generate_normal_dataset(num_samples: int = 1200, output_csv: str = "logs/features_normal_traffic.csv"):
    print(f"[*] Generando {num_samples} muestras de tráfico benigno (normal)...")
    records = []
    access_logs = []
    
    start_time = time.time() - (num_samples * 2) # simular ventana temporal de 40 minutos

    for i in range(num_samples):
        template, method, body_type = random.choice(NORMAL_PATHS)
        term = random.choice(NORMAL_SEARCH_TERMS)
        item_id = random.randint(1, 45)
        
        path = template.format(term=term, id=item_id)
        if body_type == "LOGIN_BODY":
            body = json.dumps({"email": f"customer{item_id}@example.com", "password": f"Password{item_id}!"})
        else:
            body = ""
        url = f"http://localhost:8080{path}"
        
        # Simular variabilidad natural en peticiones normales
        req_per_minute = random.randint(3, 25) # tráfico humano / cliente legítimo
        client_ip = f"192.168.1.{random.randint(10, 50)}"
        timestamp = start_time + (i * 2) + random.uniform(0.1, 1.5)
        
        row_data = {
            'url': url,
            'body': body,
            'req_per_minute': req_per_minute
        }
        
        features = extract(row_data)
        records.append(features)
        
        access_log_entry = {
            "timestamp": timestamp,
            "iso_time": datetime.fromtimestamp(timestamp).isoformat() + "Z",
            "client_ip": client_ip,
            "method": method,
            "url": url,
            "path": path,
            "body": body,
            "status_code": 200,
            "req_per_minute": req_per_minute
        }
        access_logs.append(access_log_entry)

    # Guardar CSV de características para entrenamiento
    df = pd.DataFrame(records)
    df.to_csv(output_csv, index=False)
    print(f"[+] Dataset de características guardado exitosamente en: {output_csv}")
    print(f"    Total de filas: {len(df)}")
    print(f"    Columnas: {list(df.columns)}")

    # Guardar logs de acceso estructurados
    with open("logs/access.log", "w", encoding="utf-8") as f:
        for entry in access_logs:
            f.write(json.dumps(entry) + "\n")
    print(f"[+] Logs de acceso guardados en: logs/access.log ({len(access_logs)} entradas)")

    return df

if __name__ == '__main__':
    generate_normal_dataset()

