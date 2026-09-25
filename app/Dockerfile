FROM python:3.11-slim
# Se fija a Debian 12 "bookworm" en vez de la base por defecto (Debian 13 "trixie")
# porque trixie tenía 42 CVEs HIGH sin parche aún; bookworm es una versión LTS
# más madura con más vulnerabilidades ya corregidas (hallazgo de Trivy en Fase 5).

# Crear usuario sin privilegios para pasar escaneo de seguridad Checkov/Trivy
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .
RUN mkdir -p logs && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

ENV PORT=5000 \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/').read()" || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]

