FROM python:3.11-slim
WORKDIR /app
RUN apt-get update \
 && apt-get install -y wireguard-tools nginx --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /app/
RUN python3 -m venv venv \
 && ./venv/bin/pip install --no-cache-dir -r requirements.txt
COPY . /app
EXPOSE 80
ENTRYPOINT ["/app/venv/bin/supervisord", "-c", "/app/supervisord.conf"]
