# rasp_agent.py — middleware y decorador RASP simplificado (Flask/WSGI) para la app objetivo
# Taller WAAP: Fase 4 - Runtime Application Self-Protection

import re
import functools
import logging
import json
import time
from datetime import datetime
from flask import request, abort, jsonify

# Configuración del Logger de RASP
logger = logging.getLogger('rasp')
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s] [RASP] %(levelname)s: %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# Patrones de ataque en tiempo de ejecución (según especificación Sección 4.1 del Taller)
SQLI_PATTERN = re.compile(r"(\bUNION\b|\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|--|;\s*DROP\b)", re.I)

# Variable de control para activar o desactivar RASP en pruebas de latencia (Fase 4.2)
RASP_ACTIVE = True

def set_rasp_status(active: bool):
    global RASP_ACTIVE
    RASP_ACTIVE = active
    logger.info("Estado de RASP actualizado a: %s", "ACTIVO" if active else "INACTIVO")

def is_rasp_active() -> bool:
    return RASP_ACTIVE

def log_rasp_event(event_type: str, details: str, blocked: bool):
    """Registra eventos estructurados de RASP para correlación y observabilidad."""
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "component": "RASP",
        "event_type": event_type,
        "details": details,
        "blocked": blocked,
        "client_ip": request.remote_addr if request else "internal"
    }
    try:
        with open("logs/rasp_events.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass

def rasp_guard_query(query_builder_func):
    """
    Decorador que envuelve la construcción real de la consulta SQL
    dentro de la aplicación, con visibilidad del valor final ya
    concatenado -- después de cualquier decodificación o fragmentación previa.
    """
    @functools.wraps(query_builder_func)
    def wrapper(*args, **kwargs):
        final_query = query_builder_func(*args, **kwargs)

        if not is_rasp_active():
            # Si RASP está deshabilitado para pruebas comparativas de latencia
            return final_query

        # Inspección profunda del query final resultante
        if SQLI_PATTERN.search(final_query):
            logger.warning('RASP: consulta SQL bloqueada en tiempo de ejecucion: %s', final_query)
            log_rasp_event("SQL_INJECTION_DETECTED", final_query, blocked=True)
            abort(403, description='Operacion bloqueada por RASP: Sentencia SQL insegura detectada en tiempo de ejecucion')

        return final_query
    return wrapper

@rasp_guard_query
def build_login_query(username: str, password: str) -> str:
    """
    Ejemplo deliberadamente vulnerable a nivel de construcción de la
    consulta; el RASP intercepta el resultado final antes de ejecutarlo.
    Demuestra efectividad frente a inyección clásica y fragmentada en 2 parámetros.
    """
    return f"SELECT * FROM users WHERE user='{username}' AND pass='{password}'"

@rasp_guard_query
def build_search_query(term: str) -> str:
    """Consulta de búsqueda con posible inyección en tiempo de ejecución."""
    return f"SELECT * FROM products WHERE name LIKE '%{term}%'"