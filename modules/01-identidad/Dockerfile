FROM python:3.12-slim

WORKDIR /app

# Instalamos curl para que el CI pueda hacer el healthcheck
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

# El CI y el docker-compose esperan el servicio en el puerto interno 80 (GET /health).
EXPOSE 80
CMD ["gunicorn", "--bind", "0.0.0.0:80", "app:app"]
