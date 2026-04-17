# Operations

This document covers deployment, monitoring, and troubleshooting for cert-watch.

## Deployment Options

### Option 1: Direct Python (Development/Small Scale)

```bash
# Install
pip install -e .

# Run
cert-watch
```

### Option 2: Systemd Service (Linux Production)

Create `/etc/systemd/system/cert-watch.service`:

```ini
[Unit]
Description=Cert-Watch TLS Certificate Monitor
After=network.target

[Service]
Type=simple
User=certwatch
Group=certwatch
WorkingDirectory=/opt/cert-watch
Environment=PATH=/opt/cert-watch/venv/bin
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=/opt/cert-watch/.env
ExecStart=/opt/cert-watch/venv/bin/cert-watch
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
# Create user
sudo useradd -r -s /bin/false certwatch

# Set up directory
sudo mkdir -p /opt/cert-watch
sudo chown certwatch:certwatch /opt/cert-watch

# Copy files and create virtualenv
sudo -u certwatch bash -c '
    cd /opt/cert-watch
    python3.12 -m venv venv
    source venv/bin/activate
    pip install -e .
'

# Create data directory
sudo mkdir -p /opt/cert-watch/data
sudo chown certwatch:certwatch /opt/cert-watch/data

# Reload systemd and start
sudo systemctl daemon-reload
sudo systemctl enable cert-watch
sudo systemctl start cert-watch

# Check status
sudo systemctl status cert-watch
sudo journalctl -u cert-watch -f
```

### Option 3: Docker

```dockerfile
# Dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy application
COPY src/ ./src/

# Create non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

CMD ["cert-watch"]
```

Build and run:

```bash
# Build
docker build -t cert-watch:latest .

# Run
docker run -d \
  --name cert-watch \
  -p 8000:8000 \
  --env-file .env \
  -v $(pwd)/data:/app/data \
  cert-watch:latest

# View logs
docker logs -f cert-watch
```

### Option 4: Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  cert-watch:
    build: .
    container_name: cert-watch
    ports:
      - "8000:8000"
    env_file:
      - .env
    volumes:
      - ./data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/')"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
```

Run:

```bash
docker-compose up -d
docker-compose logs -f
```

## Monitoring

### Health Check Endpoint

```bash
# Basic health check
curl http://localhost:8000/

# Should return HTML dashboard with 200 status
```

### Log Monitoring

**Default log locations:**

- **Systemd**: `journalctl -u cert-watch`
- **Docker**: `docker logs cert-watch`
- **Direct**: stdout/stderr

**Log levels:**
- ERROR: Connection failures, SMTP errors
- WARNING: Certificate parsing issues
- INFO: Scan completions, certificate updates
- DEBUG: Detailed operation logs (when DEBUG=true)

### Metrics to Monitor

| Metric | How to Check | Alert Threshold |
|--------|--------------|-----------------|
| Dashboard accessible | HTTP GET / = 200 | HTTP error codes |
| Certificate expiry | Dashboard status counts | Red status count > 0 |
| Scan success rate | Scheduler page | Failed hosts > 0 |
| Database size | `du -h data/*.db` | > 100 MB |
| Disk space | `df -h` | < 10% free |

### Prometheus Metrics (Future)

Planned for v2:

```
# Certificate metrics
certwatch_certificates_total{type="leaf"}
certwatch_certificates_total{type="chain"}
certwatch_certificates_expiring_days{days="7"}

# Scan metrics
certwatch_scans_total{status="success"}
certwatch_scan_duration_seconds

# Alert metrics
certwatch_alerts_sent_total
```

## Backup and Recovery

### Database Backup

```bash
# Simple file backup
sudo cp /opt/cert-watch/data/cert_watch.db /backup/cert_watch-$(date +%Y%m%d).db

# Automated daily backup via cron
0 2 * * * cp /opt/cert-watch/data/cert_watch.db /backup/cert_watch-$(date +\%Y\%m\%d).db

# Backup with verification
cp cert_watch.db cert_watch.db.bak
sqlite3 cert_watch.db "PRAGMA integrity_check;"
```

### Restore from Backup

```bash
# Stop the service
sudo systemctl stop cert-watch

# Restore database
sudo cp /backup/cert_watch-20240101.db /opt/cert-watch/data/cert_watch.db
sudo chown certwatch:certwatch /opt/cert-watch/data/cert_watch.db

# Start the service
sudo systemctl start cert-watch
```

### Export/Import Certificates

```bash
# Export certificate data (custom script)
python << 'EOF'
import asyncio
import json
from cert_watch.web.deps import get_repo

async def export():
    # Implementation for certificate export
    pass

asyncio.run(export())
EOF
```

## Troubleshooting

### Failure Mode: Dashboard Not Loading

**Symptoms**: HTTP 500 error or connection refused

**Diagnostics**:
```bash
# Check if process is running
pgrep -f cert-watch

# Check logs
journalctl -u cert-watch -n 50

# Check port binding
netstat -tlnp | grep 8000
```

**Solutions**:
1. **Port already in use**: Change port or kill existing process
2. **Database permission error**: Fix ownership of data directory
3. **Missing dependencies**: Reinstall with `pip install -e .`

### Failure Mode: TLS Scanning Fails

**Symptoms**: "Connection failed" or "TLS handshake failed" errors

**Diagnostics**:
```bash
# Test TLS connection manually
openssl s_client -connect hostname:443 -servername hostname

# Check DNS resolution
nslookup hostname

# Test from Python
python -c "
import socket, ssl
try:
    sock = socket.create_connection(('hostname', 443), timeout=10)
    ctx = ssl.create_default_context()
    ssock = ctx.wrap_socket(sock, server_hostname='hostname')
    print('TLS OK')
except Exception as e:
    print(f'Error: {e}')
"
```

**Common Causes**:
1. **Network firewall**: Outbound 443 blocked
2. **DNS failure**: Hostname not resolvable
3. **Certificate validation**: Self-signed or expired chain
4. **Timeout**: Host too slow to respond (default 10s)

**Solutions**:
- Check firewall rules
- Verify hostname spelling
- Check network connectivity

### Failure Mode: Email Alerts Not Sending

**Symptoms**: Alerts shown as "pending" or "failed" in alert history

**Diagnostics**:
```bash
# Check SMTP configuration
grep SMTP .env

# Test SMTP connection manually
python -c "
import smtplib
server = smtplib.SMTP('smtp.example.com', 587)
server.starttls()
server.login('user', 'pass')
print('SMTP OK')
"
```

**Common Causes**:
1. **SMTP not configured**: Missing environment variables
2. **Authentication failure**: Wrong credentials
3. **Network blocked**: Outbound SMTP blocked by firewall
4. **TLS required**: Server requires STARTTLS

**Solutions**:
- Verify all SMTP_* variables are set
- For Gmail: Use App Password, not account password
- Check firewall allows outbound SMTP (port 587 or 465)
- Verify `SMTP_USE_TLS` setting matches server requirements

### Failure Mode: Scheduler Not Running

**Symptoms**: No automatic scans, manual scan works

**Diagnostics**:
```bash
# Check scheduler status page
curl http://localhost:8000/scheduler

# Check if scheduler started in logs
grep -i "scheduler" /var/log/cert-watch.log
```

**Common Causes**:
1. **Scheduler not started**: App started without scheduler initialization
2. **Wrong timezone**: Scan time in different timezone than expected
3. **App restarted**: Scheduler state lost on restart

**Solutions**:
- Check app startup logs for scheduler initialization
- Verify `SCAN_TIME` and `SCAN_TIMEZONE` settings
- Consider external cron job as alternative

### Failure Mode: High Memory Usage

**Symptoms**: OOM kills, slow response times

**Diagnostics**:
```bash
# Monitor memory usage
ps aux | grep cert-watch

# Check database size
du -h data/*.db
```

**Causes**:
1. **Large certificate chains**: Storing full PEM data for many certs
2. **Memory leak**: Unclosed connections or circular references
3. **High concurrency**: Too many simultaneous requests

**Solutions**:
- Archive old certificates
- Restart service periodically via cron
- Limit concurrent connections

### Failure Mode: Database Corruption

**Symptoms**: SQLite errors, "database disk image is malformed"

**Diagnostics**:
```bash
# Check database integrity
sqlite3 cert_watch.db "PRAGMA integrity_check;"

# Check file corruption
file cert_watch.db
```

**Recovery**:
1. Stop the application
2. Restore from latest backup
3. If no backup, attempt SQLite recovery:
   ```bash
   sqlite3 cert_watch.db ".dump" > dump.sql
   sqlite3 new.db < dump.sql
   ```

## Log Reference

### Common Log Messages

| Message | Level | Meaning |
|---------|-------|---------|
| `Scheduler started. Daily scan scheduled for 06:00` | INFO | Scheduler initialized successfully |
| `Daily scan completed: 5/5 hosts successful` | INFO | Scan cycle finished normally |
| `Failed to scan hostname:port` | WARNING | Individual host scan failed |
| `SMTP error: ...` | ERROR | Email sending failed |
| `Invalid certificate file` | WARNING | Upload rejected - bad format |

### Debug Logging

Enable debug logging:

```env
DEBUG=true
```

Or programmatically:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Security Hardening

### File Permissions

```bash
# Database file
chmod 640 cert_watch.db
chown certwatch:certwatch cert_watch.db

# Environment file
chmod 600 .env
chown certwatch:certwatch .env

# Application directory
chmod 755 /opt/cert-watch
```

### Network Security

- Run behind reverse proxy (nginx, traefik) for TLS termination
- Use firewall rules to restrict access to dashboard
- Consider VPN or internal network for dashboard access

### Reverse Proxy Configuration (nginx)

```nginx
server {
    listen 443 ssl;
    server_name certwatch.yourcompany.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Maintenance Tasks

### Daily

- Check dashboard for red/yellow certificates
- Review alert history for failed sends

### Weekly

- Review scan history for persistent failures
- Check disk space and database size

### Monthly

- Clean up old scan history (if needed)
- Verify backup integrity
- Review and update alert recipient list

### Quarterly

- Update dependencies: `pip install -e . --upgrade`
- Review access logs for unauthorized access attempts
- Test disaster recovery procedure
