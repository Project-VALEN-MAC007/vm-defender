# Company web app (same image for production and honeypot; BACKEND picks the data).
FROM python:3.12-slim
RUN useradd --system --uid 10002 --no-create-home --shell /usr/sbin/nologin trapweb
WORKDIR /opt/trap
COPY webapp /opt/trap/webapp
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 WEBAPP_HOST=0.0.0.0 WEBAPP_PORT=8080
USER 10002
EXPOSE 8080
# BACKEND must be set by compose: real on Project-Web, decoy on the Honeypot.
ENTRYPOINT ["python3", "-m", "webapp.app"]
