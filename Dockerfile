# SPDX-License-Identifier: AGPL-3.0-or-later
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 relay
COPY relay ./relay
USER relay
EXPOSE 8080
# No access log: the relay does not record who called it. Run the container read-only (see README).
CMD ["uvicorn", "relay.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips", "*"]
