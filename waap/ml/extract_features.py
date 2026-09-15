# extract_features.py - extraccion de caracteristicas de un log de acceso
import re, math, pandas as pd
def shannon_entropy(s):
    if not s:
       return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(pr * math.log2(pr) for pr in probs)
SUSPICIOUS = re.compile(r"(--|;|<script|\.\./|\bUNION\b|\bOR\b\s+1=1)", re.I)

def extract(request_row):
   url = request_row['url']
   body = request_row.get('body', '')
   return {'url_length': len(url), 'body_length': len(body), 'entropy': shannon_entropy(url + body), 'n_params': url.count('&') + 1 if '?' in url else 0, 'has_suspicious_chars': bool(SUSPICIOUS.search(url + body)),'req_per_minute': request_row.get('req_per_minute', 0),}
