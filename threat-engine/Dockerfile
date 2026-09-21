FROM python:3.11-slim

WORKDIR /app

# System deps needed by xgboost's OpenMP runtime
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY train ./train

# Bake a trained model into the image so the container is self-contained
# and starts instantly. For a real deployment, swap this for a scheduled
# retraining job that writes to a shared model store (S3/GCS) and have the
# service pull the latest artifact on startup -- see "Production Hardening"
# in the write-up.
RUN python train/train_model.py

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
