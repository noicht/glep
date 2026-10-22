FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY server.py /app/server.py

# Sin privilegios y con root filesystem de solo lectura (ver compose).
USER 65534:65534

EXPOSE 18080 12222 16379
CMD ["python", "-u", "/app/server.py"]
