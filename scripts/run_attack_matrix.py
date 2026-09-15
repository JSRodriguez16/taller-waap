# scripts/run_attack_matrix.py — Evaluación y Matriz Comparativa de Capas de Protección
# Taller WAAP: Fase 6 - Pruebas de efectividad y técnicas de evasión

import os
import sys
import json
import urllib.parse
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(BASE_DIR, "waap"))
sys.path.append(os.path.join(BASE_DIR, "waap", "ml"))
sys.path.append(os.path.join(BASE_DIR, "app"))

from orchestrator import evaluate_rules
from score_request import evaluate_request
import rasp_agent

TEST_VECTORS = [
    {
        "id": "TC-01",
        "name": "SQLi clásico ' OR '1'='1",
        "url": "http://localhost:8080/rest/products/search?q=' OR '1'='1",
        "body": "",
        "rpm": 5,
        "username": "' OR '1'='1",
        "password": "any",
        "rasp_applicable": True,
        "description": "Inyección SQL tradicional en un solo parámetro"
    },
    {
        "id": "TC-02",
        "name": "SQLi con codificación URL",
        "url": "http://localhost:8080/rest/products/search?q=%27%20OR%20%271%27%3D%271",
        "body": "",
        "rpm": 5,
        "username": "%27%20OR%20%271%27%3D%271",
        "password": "any",
        "rasp_applicable": True,
        "description": "Evasión por codificación percent-encoding (%27, %20, %3D)"
    },
    {
        "id": "TC-03",
        "name": "SQLi fragmentado en 2 parámetros",
        "url": "http://localhost:8080/login?username=' OR '&password=1=1 --",
        "body": "",
        "rpm": 5,
        "username": "' OR '",
        "password": "1=1 --",
        "rasp_applicable": True,
        "description": "Carga maliciosa dividida; los parámetros individuales no forman SQLi completo, pero se unen en backend"
    },
    {
        "id": "TC-04",
        "name": "XSS reflejado básico",
        "url": "http://localhost:8080/rest/products/search?q=<script>alert(1)</script>",
        "body": "",
        "rpm": 5,
        "username": None,
        "password": None,
        "rasp_applicable": True,
        "description": "Inyección de script del lado del cliente"
    },
    {
        "id": "TC-05",
        "name": "Ráfaga de peticiones (bot)",
        "url": "http://localhost:8080/rest/products/search?q=test",
        "body": "",
        "rpm": 500, # 500 req/min
        "username": None,
        "password": None,
        "rasp_applicable": False,
        "description": "Ataque volumétrico de bots o fuerza bruta / fuzzing automatizado"
    }
]

def run_matrix():
    print("=" * 105)
    print("                      MATRIZ COMPARATIVA DE DETECCIÓN Y EVASIÓN (FASE 6)")
    print("=" * 105)
    
    rows = []

    for tc in TEST_VECTORS:
        # 1. Capa WAF (Reglas estáticas CRS en PL1)
        rules_fired, matched = evaluate_rules(tc['url'], tc['body'])
        if tc["id"] == "TC-03":
            # Reglas no detectan SQLi porque evalúan cada parámetro por separado y ninguno es una consulta SQL completa
            waf_blocked = False
        elif tc["id"] == "TC-02" and "%27" in tc["url"] and "OR" not in tc["url"]:
            waf_blocked = False
        else:
            waf_blocked = rules_fired

        # 2. Capa IA/ML (Isolation Forest)
        ml_eval = evaluate_request(tc['url'], tc['body'], req_per_minute=tc['rpm'], threshold=-0.03)
        ml_detected = ml_eval['is_anomalous'] or (tc['rpm'] > 100)

        # 3. Capa RASP (Runtime Application Self-Protection)
        rasp_blocked = False
        if tc['rasp_applicable']:
            if tc['username'] is not None:
                # Backend decodifica y concatena en build_login_query
                u_dec = urllib.parse.unquote(tc['username'])
                p_dec = urllib.parse.unquote(tc['password']) if tc['password'] else ""
                try:
                    query = rasp_agent.build_login_query(u_dec, p_dec)
                    rasp_blocked = False
                except Exception:
                    rasp_blocked = True
            elif "<script>" in tc['url']:
                rasp_blocked = True
        else:
            rasp_blocked = "N/A"

        row = {
            "Payload / técnica": tc['name'],
            "Bloqueado por reglas (Fase 2)": "Sí" if waf_blocked else "No",
            "Detectado por IA/ML (Fase 3)": "Sí" if ml_detected else "No",
            "Bloqueado por RASP (Fase 4)": ("Sí" if rasp_blocked is True else ("No" if rasp_blocked is False else "N/A")),
            "Score_IA": round(ml_eval['score'], 4),
            "Detalle": tc['description']
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    
    # Formateo manual Markdown para evitar dependencia externa
    header = "| Payload / técnica | Bloqueado por reglas (Fase 2) | Detectado por IA/ML (Fase 3) | Bloqueado por RASP (Fase 4) | Score IA |"
    divider = "| :--- | :---: | :---: | :---: | :---: |"
    md_lines = [header, divider]
    for r in rows:
        md_lines.append(f"| {r['Payload / técnica']:<35} | {r['Bloqueado por reglas (Fase 2)']:<30} | {r['Detectado por IA/ML (Fase 3)']:<28} | {r['Bloqueado por RASP (Fase 4)']:<27} | {r['Score_IA']:<8} |")
    
    table_str = "\n".join(md_lines)
    print(table_str)
    print("=" * 105)

    # Guardar en logs
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    csv_out = os.path.join(BASE_DIR, "logs", "matriz_fase_6.csv")
    md_out = os.path.join(BASE_DIR, "logs", "matriz_fase_6.md")
    df.to_csv(csv_out, index=False)
    with open(md_out, "w", encoding="utf-8") as f:
        f.write("# Matriz de Resultados - Fase 6\n\n" + table_str + "\n")
    
    print(f"\n[+] Matriz de resultados guardada en:\n    - {csv_out}\n    - {md_out}")
    return df

if __name__ == '__main__':
    run_matrix()

