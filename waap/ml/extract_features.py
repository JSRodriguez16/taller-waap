# waap/ml/extract_features.py — Extracción de características estadísticas y heurísticas de tráfico HTTP
# Taller WAAP: Fase 3 - Módulo de detección basado en IA/ML

import re
import math
import urllib.parse
from typing import Dict, Any, Union

def shannon_entropy(s: str) -> float:
    """Calcula la entropía de Shannon de una cadena de texto."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(pr * math.log2(pr) for pr in probs)

# Regex para patrones sospechosos típicos (SQLi, XSS, Path Traversal, Comandos)
SUSPICIOUS = re.compile(r"(--|;|<script|\.\./|\bUNION\b|\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|\bSELECT\b|\bDROP\b)", re.I)

def extract(request_row: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
    """
    Extrae vector de características numéricas a partir de los datos de una petición.
    Características:
      - url_length: Longitud de la URL
      - body_length: Longitud del cuerpo (payload)
      - entropy: Entropía de Shannon combinada de URL y body
      - n_params: Cantidad de parámetros en query string
      - has_suspicious_chars: Indicador binario (1.0 o 0.0) de presencia de patrones sospechosos
      - req_per_minute: Frecuencia de peticiones en ventana temporal (detección de bots/fuzzing)
    """
    if isinstance(request_row, dict):
        url = str(request_row.get('url', ''))
        body = str(request_row.get('body', '') or '')
        rpm = float(request_row.get('req_per_minute', 1))
    else:
        # Soporte para filas de DataFrame de pandas
        url = str(request_row['url'])
        body = str(request_row.get('body', '') if 'body' in request_row else '')
        rpm = float(request_row['req_per_minute']) if 'req_per_minute' in request_row else 1.0

    # Decodificación URL para análisis profundo y cálculo de entropía
    try:
        decoded_content = urllib.parse.unquote(url + body)
    except Exception:
        decoded_content = url + body

    content = url + body
    has_suspicious = bool(SUSPICIOUS.search(content) or SUSPICIOUS.search(decoded_content))

    return {
        'url_length': float(len(url)),
        'body_length': float(len(body)),
        'entropy': float(shannon_entropy(content)),
        'n_params': float(url.count('&') + 1 if '?' in url else 0),
        'has_suspicious_chars': 1.0 if has_suspicious else 0.0,
        'req_per_minute': rpm,
    }

if __name__ == '__main__':
    sample = {"url": "http://localhost:8080/rest/products/search?q=apple", "body": "", "req_per_minute": 5}
    print("Muestra normal:", extract(sample))
    attack = {"url": "http://localhost:8080/rest/products/search?q=' OR 1=1 --", "body": "", "req_per_minute": 5}
    print("Muestra ataque:", extract(attack))
