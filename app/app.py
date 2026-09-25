# app/app.py — Aplicación web Flask instrumentada con agente RASP
# Taller WAAP - Fase 1, Fase 4 y Fase 5

import os
import time
import json
import logging
from flask import Flask, request, jsonify, render_template_string
from rasp_agent import (
    build_login_query,
    build_search_query,
    set_rasp_status,
    is_rasp_active,
    log_rasp_event
)

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('target-app')

# Asegurar directorio de logs
os.makedirs("logs", exist_ok=True)

# Middleware para registrar cada petición en logs/access.log
@app.before_request
def log_request_info():
    request.start_time = time.time()

@app.after_request
def log_response_info(response):
    duration = time.time() - getattr(request, 'start_time', time.time())
    log_entry = {
        "timestamp": time.time(),
        "method": request.method,
        "path": request.path,
        "url": request.url,
        "remote_addr": request.remote_addr,
        "status_code": response.status_code,
        "body": request.get_data(as_text=True),
        "duration_ms": round(duration * 1000, 2)
    }
    try:
        with open("logs/access.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception:
        pass
    return response

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "service": "Taller WAAP Vulnerable Target App + RASP",
        "rasp_active": is_rasp_active(),
        "endpoints": [
            "/login (POST: username, password)",
            "/rest/products/search?q=... (GET)",
            "/rasp/toggle (POST: active=true/false)"
        ]
    })

@app.route('/login', methods=['GET', 'POST'])
@app.route('/rest/user/login', methods=['GET', 'POST'])
def login():
    """
    Endpoint de Login vulnerable a SQL Injection.
    Soporta:
      - Payload SQLi clásico: ' OR '1'='1
      - Payload SQLi fragmentado: username="' OR '" y password="1=1 --"
    El agente RASP intercepta la llamada a build_login_query() antes de ejecutarla.
    """
    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form.to_dict()
        username = data.get('username', '')
        password = data.get('password', '')
    else:
        username = request.args.get('username', '')
        password = request.args.get('password', '')

    # Construcción de la consulta (interceptada por @rasp_guard_query)
    query = build_login_query(username, password)

    # Simulación de ejecución en base de datos si RASP no bloqueó
    logger.info("Consulta SQL ejecutada en base de datos: %s", query)
    
    # Si la consulta contiene inyección y no fue bloqueada (RASP apagado)
    if "OR" in query or "--" in query:
        return jsonify({
            "status": "success",
            "message": "Autenticacion exitosa como Administrador (Vulnerable a SQLi)",
            "user": "admin",
            "query_executed": query
        }), 200

    if username == "admin" and password == "secret123":
        return jsonify({"status": "success", "message": "Bienvenido admin"}), 200

    return jsonify({"status": "failed", "message": "Credenciales invalidas"}), 401

@app.route('/search', methods=['GET'])
@app.route('/rest/products/search', methods=['GET'])
def search():
    """
    Búsqueda con salida HTML escapada.
    Conserva la construcción de consultas del laboratorio RASP.
    """
    q = request.args.get('q', '')

    # Interceptado por RASP
    query = build_search_query(q)
    logger.info("Búsqueda ejecutada: %s", query)

    html_template = """
    <html>
      <body>
        <h2>Resultados para: {{ q }}</h2>
        <p>No se encontraron productos coincidentes.</p>
      </body>
    </html>
    """
    return render_template_string(html_template, q=q), 200

@app.route('/rasp/toggle', methods=['POST'])
def toggle_rasp():
    """Permite habilitar o deshabilitar RASP dinámicamente para medir latencia."""
    data = request.get_json(silent=True) or {}
    active = data.get('active', True)
    set_rasp_status(active)
    return jsonify({
        "rasp_active": is_rasp_active(),
        "message": f"RASP ahora esta {'habilitado' if is_rasp_active() else 'deshabilitado'}"
    })

@app.route('/rasp/status', methods=['GET'])
def rasp_status():
    return jsonify({"rasp_active": is_rasp_active()})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port, debug=False)

