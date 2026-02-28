FROM python:3.11-slim

WORKDIR /ghostwall

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DRY_RUN=true
ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
