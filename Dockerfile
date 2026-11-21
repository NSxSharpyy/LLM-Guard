FROM python:3.12-slim

WORKDIR /app

ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1

COPY requirements-docker.txt .
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "src.proxy.proxy_server:app", "--host", "0.0.0.0", "--port", "8000"]
