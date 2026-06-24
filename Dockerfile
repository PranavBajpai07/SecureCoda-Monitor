FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY securecoda ./securecoda
COPY README.md ./

RUN adduser --disabled-password --gecos "" appuser && \
    mkdir -p /app/data /app/logs && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "securecoda.main:app", "--host", "0.0.0.0", "--port", "8000"]

