# waap/orchestrator.py — Orquestador de Decisión Multi-Capa WAAP (Reglas + IA/ML + RASP)
# Taller WAAP: Sección 4 - Arquitectura de Referencia del Laboratorio

import os
import sys
import re
import json
import time
from datetime import datetime
from typing import Dict, Any, Tuple

# Rutas del proyecto
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(BASE_DIR, "waap", "ml"))
sys.path.append(os.path.join(BASE_DIR, "app"))

from extract_features import extract
from score_request import score, evaluate_request
import rasp_agent

# Motor de reglas declarativas en memoria (emulación de firmas OWASP CRS / Coraza)
CRS_RULES = [
    {
        "id": 942100,
        "name": "SQLi - Operator Detection",
        "pattern": re.compile(r"(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|\bUNION\b\s+\bSELECT\b)", re.I),
        "target": ["url", "body"]
    },
    {
        "id": 942140,
        "name": "SQLi - Common Comment / Query Delimiter",
        "pattern": re.compile(r"(--|/\*.*?\*/|;\s*DROP\b)", re.I),
        "target": ["url", "body"]
    },
    {
        "id": 941100,
        "name": "XSS - Tag / Script Injection",
        "pattern": re.compile(r"(<script.*?>|javascript:|onload\s*=|onerror\s*=)", re.I),
        "target": ["url", "body"]
    },
    {
        "id": 930100,
        "name": "Path Traversal - Directory Climbing",
        "pattern": re.compile(r"(\.\./|\.\.\\)", re.I),
        "target": ["url"]
    }
]

LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
SECURITY_LOG_FILE = os.path.join(LOGS_DIR, "security_events.jsonl")

def log_event(event_dict: Dict[str, Any]):
    """Registra eventos centralizados en formato JSON estructurado para observabilidad y SIEM."""
    event_dict["timestamp"] = datetime.utcnow().isoformat() + "Z"
    event_dict["epoch"] = time.time()
    try:
        with open(SECURITY_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_dict) + "\n")
    except Exception as e:
        print(f"[!] Error escribiendo en log de seguridad: {e}")

def evaluate_rules(url: str, body: str = "") -> Tuple[bool, list]:
    """
    Capa 1: Motor de reglas (Coraza / ModSecurity + CRS).
    Retorna (disparado: bool, lista_de_reglas_coincidentes).
    Nota: Las reglas estándar analizan el parámetro tal como llega en la petición HTTP cruda;
    no ven fragmentaciones divididas entre múltiples parámetros separados.
    """
    matches = []
    # Evaluar sobre URL cruda y cuerpo
    for rule in CRS_RULES:
        check_text = ""
        if "url" in rule["target"]:
            check_text += url + " "
        if "body" in rule["target"]:
            check_text += body + " "
        
        if rule["pattern"].search(check_text):
            matches.append({"id": rule["id"], "name": rule["name"]})
    
    return (len(matches) > 0, matches)

def orchestrate(url: str, body: str = "", req_per_minute: float = 1.0, 
                username: str = None, password: str = None,
                threshold_block: float = -0.04, threshold_challenge: float = 0.0) -> Dict[str, Any]:
    """
    Orquestador central:
      Paso 1: Motor de Reglas (Firmas)
      Paso 2: Módulo IA/ML (Score de anomalía)
      Paso 3: Decisión combinada (ALLOW / CHALLENGE / BLOCK)
      Paso 4: Si se permite el paso, Agente RASP (Inspección en tiempo de ejecución del backend)
    """
    start_time = time.time()
    
    # 1. Evaluación de Reglas
    rules_fired, matched_rules = evaluate_rules(url, body)

    # 2. Evaluación de IA/ML
    ml_eval = evaluate_request(url, body, req_per_minute, threshold=threshold_block)
    ml_score = ml_eval["score"]

    # 3. Orquestador de Decisión
    verdict = "ALLOW"
    reason = "Petición limpia y benigna"

    if rules_fired:
        verdict = "BLOCK"
        reason = f"Bloqueado por Motor de Reglas CRS ({[r['name'] for r in matched_rules]})"
    elif ml_score < threshold_block:
        verdict = "BLOCK"
        reason = f"Bloqueado por IA/ML (Score anómalo severo: {ml_score} < {threshold_block})"
    elif ml_score < threshold_challenge or req_per_minute > 100:
        verdict = "CHALLENGE"
        reason = f"Desafío activado (CAPTCHA/Proof of Work): Score={ml_score}, RPM={req_per_minute}"

    # 4. Agente RASP (si pasa o para inspección interna de la aplicación)
    rasp_blocked = False
    rasp_details = None

    # Simular llamada sensible en backend si se pasan credenciales
    if username is not None or password is not None:
        try:
            query = rasp_agent.build_login_query(username or "", password or "")
            rasp_details = f"Query ejecutado: {query}"
        except Exception as e:
            # RASP bloqueó
            rasp_blocked = True
            rasp_details = str(e)
            if verdict == "ALLOW":
                verdict = "BLOCK"
                reason = "Bloqueado en tiempo de ejecución por Agente RASP (Deep Query Inspection)"

    detection_time_ms = round((time.time() - start_time) * 1000, 2)

    decision_result = {
        "url": url,
        "method": "POST" if body else "GET",
        "verdict": verdict,
        "reason": reason,
        "rules_layer": {
            "blocked": rules_fired,
            "matched_rules": matched_rules
        },
        "ml_layer": {
            "score": ml_score,
            "is_anomalous": ml_eval["is_anomalous"],
            "features": ml_eval["features"]
        },
        "rasp_layer": {
            "blocked": rasp_blocked,
            "details": rasp_details
        },
        "detection_time_ms": detection_time_ms
    }

    log_event(decision_result)
    return decision_result

if __name__ == '__main__':
    print("=== Probando Orquestador WAAP ===")
    r1 = orchestrate("http://localhost:8080/rest/products/search?q=apple", req_per_minute=5)
    print(f"Petición benigna: Veredicto={r1['verdict']} | Razón={r1['reason']}")

    r2 = orchestrate("http://localhost:8080/rest/products/search?q=' OR '1'='1", req_per_minute=5)
    print(f"SQLi Clásico: Veredicto={r2['verdict']} | Razón={r2['reason']}")

    # Caso de bypass de reglas: payload fragmentado entre dos parámetros
    r3 = orchestrate("http://localhost:8080/login", username="' OR '", password="1=1 --", req_per_minute=5)
    print(f"SQLi Fragmentado: Veredicto={r3['verdict']} | Razón={r3['reason']}")

