FROM python:3.12-slim

LABEL org.opencontainers.image.title="cidr-pull"
LABEL org.opencontainers.image.description="Residential ISP Whitelist — ASN/CIDR fetcher & AbuseIPDB auditor"

# Non-root user
RUN useradd -m -u 1000 cidrpull
WORKDIR /app

# Dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cidr_pull.py .

# Persistent volume for SQLite cache and output files
RUN mkdir -p /data && chown cidrpull:cidrpull /data
VOLUME ["/data"]

USER cidrpull

ENV CIDR_CACHE_DIR=/data/.cidr_pull

ENTRYPOINT ["python3", "cidr_pull.py", "--cache-dir", "/data/.cidr_pull"]
CMD ["--help"]
