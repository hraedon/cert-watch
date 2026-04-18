# cert-watch Kubernetes Operations Guide

This guide covers deploying and operating cert-watch in Kubernetes.

## Quick Start

```bash
# Apply all manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Or use kustomize
kubectl apply -k k8s/

# Create secrets (REQUIRED for email alerts)
kubectl create secret generic cert-watch-secrets \
  --from-literal=smtp-host='smtp.gmail.com' \
  --from-literal=smtp-user='your-email@gmail.com' \
  --from-literal=smtp-password='your-app-password' \
  --from-literal=smtp-from-addr='alerts@example.com' \
  --from-literal=alert-recipients='admin@example.com' \
  -n cert-watch

# Port-forward to access locally
kubectl port-forward -n cert-watch svc/cert-watch 8000:8000
```

## Configuration

### Required: SMTP Secrets

cert-watch requires SMTP configuration to send email alerts. Create the secret:

```bash
kubectl create secret generic cert-watch-secrets \
  --from-literal=smtp-host='smtp.example.com' \
  --from-literal=smtp-user='username' \
  --from-literal=smtp-password='password' \
  --from-literal=smtp-from-addr='alerts@example.com' \
  --from-literal=alert-recipients='admin@example.com,ops@example.com' \
  -n cert-watch
```

### Optional: ConfigMap Changes

Edit `k8s/configmap.yaml` to customize:

- `SCAN_TIME` — Daily scan time (HH:MM format, default: 06:00)
- `SCAN_TIMEZONE` — Timezone for scheduler (default: UTC)
- `LEAF_ALERT_THRESHOLDS` — Comma-separated days before expiry (default: 14,7,3,1)
- `CHAIN_ALERT_THRESHOLDS` — Comma-separated days before expiry (default: 30,14,7)

After editing, apply and restart:

```bash
kubectl apply -f k8s/configmap.yaml
kubectl rollout restart deployment/cert-watch -n cert-watch
```

## Deployment Procedures

### Initial Deployment

```bash
# 1. Create namespace and storage
kubectl apply -f k8s/namespace.yaml -f k8s/pvc.yaml

# 2. Apply configuration
kubectl apply -f k8s/configmap.yaml

# 3. Create secrets (REQUIRED)
kubectl create secret generic cert-watch-secrets \
  --from-literal=smtp-host='smtp.example.com' \
  --from-literal=smtp-password='secret' \
  --from-literal=alert-recipients='ops@example.com' \
  -n cert-watch

# 4. Deploy application
kubectl apply -f k8s/deployment.yaml -f k8s/service.yaml

# 5. Verify
kubectl get pods -n cert-watch
kubectl logs -n cert-watch -l app.kubernetes.io/name=cert-watch
```

### Production Deployment

For production, use Kustomize overlays:

```bash
# Production overlay (create overlays/production/)
kubectl apply -k overlays/production/

# Or with patches
kubectl apply -k k8s/ --overlay=overlays/production
```

## Scaling

### Horizontal Scaling

```bash
# Scale to 3 replicas
kubectl scale deployment cert-watch -n cert-watch --replicas=3

# Verify
kubectl get pods -n cert-watch
```

**Note:** SQLite has concurrent write limitations. Multiple replicas work but may have brief contention during scans. For high-volume deployments, consider:
- Single replica with resource scaling
- External database (PostgreSQL/MySQL) future enhancement

### Vertical Scaling

Edit `k8s/deployment.yaml` resources section:

```yaml
resources:
  requests:
    memory: "256Mi"  # Increase from 128Mi
    cpu: "200m"      # Increase from 100m
  limits:
    memory: "1Gi"    # Increase from 512Mi
    cpu: "1000m"     # Increase from 500m
```

Then apply:
```bash
kubectl apply -f k8s/deployment.yaml
```

## Upgrades

### Rolling Update

```bash
# Update image and trigger rollout
kubectl set image deployment/cert-watch cert-watch=cert-watch:v0.2.0 -n cert-watch

# Monitor progress
kubectl rollout status deployment/cert-watch -n cert-watch

# Check history
kubectl rollout history deployment/cert-watch -n cert-watch

# Rollback if needed
kubectl rollout undo deployment/cert-watch -n cert-watch
```

### Configuration Update

```bash
# Update ConfigMap
kubectl apply -f k8s/configmap.yaml

# Restart to pick up new config
kubectl rollout restart deployment/cert-watch -n cert-watch
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod status
kubectl get pods -n cert-watch

# Describe for events
kubectl describe pod -n cert-watch -l app.kubernetes.io/name=cert-watch

# Check logs
kubectl logs -n cert-watch -l app.kubernetes.io/name=cert-watch

# Previous container logs (if crashed)
kubectl logs -n cert-watch -l app.kubernetes.io/name=cert-watch --previous
```

### Common Issues

**Pod stuck in Pending:**
```bash
# Check PVC binding
kubectl get pvc -n cert-watch
# If pending, check storage class availability
kubectl get storageclass
```

**Email alerts not sending:**
```bash
# Verify secrets exist
kubectl get secret cert-watch-secrets -n cert-watch

# Check logs for SMTP errors
kubectl logs -n cert-watch -l app.kubernetes.io/name=cert-watch | grep -i smtp
```

**Database locked errors:**
- Normal with SQLite + multiple replicas during concurrent scans
- Reduce to single replica: `kubectl scale deployment cert-watch -n cert-watch --replicas=1`

### Debug Commands

```bash
# Shell into running pod
kubectl exec -n cert-watch -it deploy/cert-watch -- /bin/sh

# Check data directory
kubectl exec -n cert-watch -it deploy/cert-watch -- ls -la /app/data

# View database
kubectl exec -n cert-watch -it deploy/cert-watch -- sqlite3 /app/data/cert_watch.db ".tables"

# Test SMTP connectivity
kubectl exec -n cert-watch -it deploy/cert-watch -- python -c "
import socket
s = socket.socket()
s.connect(('smtp.gmail.com', 587))
print('Connected to SMTP')
s.close()
"
```

## Data Management

### Backup

```bash
# Copy database from pod to local
kubectl cp cert-watch/cert-watch-0:/app/data/cert_watch.db ./cert_watch-backup.db

# Or copy from PVC directly (requires understanding your storage provider)
```

### Restore

```bash
# Scale down first
kubectl scale deployment cert-watch -n cert-watch --replicas=0

# Copy backup to pod
kubectl cp ./cert_watch-backup.db cert-watch/cert-watch-0:/app/data/cert_watch.db

# Scale back up
kubectl scale deployment cert-watch -n cert-watch --replicas=2
```

## Monitoring

### Health Checks

The deployment includes:
- **Liveness probe** — Restarts pod if app unresponsive
- **Readiness probe** — Removes pod from service if not ready

### Resource Monitoring

```bash
# Watch resource usage
kubectl top pods -n cert-watch

# Watch logs
kubectl logs -n cert-watch -l app.kubernetes.io/name=cert-watch -f
```

## Security

- **Non-root container:** Runs as user 1000
- **Read-only root filesystem:** Application code is immutable
- **Dropped capabilities:** All Linux capabilities removed
- **Seccomp:** Runtime default profile applied
- **Secrets:** SMTP credentials stored in Kubernetes secrets

## Support

For issues:
1. Check logs: `kubectl logs -n cert-watch -l app.kubernetes.io/name=cert-watch`
2. Review this guide
3. Check [README.md](../README.md) for application documentation
