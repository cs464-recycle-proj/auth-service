# Auth Service Helm Chart

## Overview
This Helm chart deploys the Authentication Service to Kubernetes with PostgreSQL database support.

## Prerequisites
- Kubernetes cluster (1.19+)
- Helm 3.x
- kubectl configured to access your cluster
- Docker registry credentials (for private registries)

## Installation

### 1. Create Secrets File
⚠️ **IMPORTANT**: Never commit secrets to git!

```bash
# Copy the example secrets file
cp values.secrets.yaml.example values.secrets.yaml

# Edit with your actual secrets
# Update: PostgreSQL password, RabbitMQ password, etc.
```

### 2. Add Bitnami repository (for PostgreSQL dependency)
```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
```

### 3. Install the chart
```bash
# From the project root directory
cd helm

# Install with default values + your secrets
helm install auth-service . \
  --namespace auth \
  --create-namespace \
  -f values.yaml \
  -f values.secrets.yaml
```

### 4. Check deployment status
```bash
kubectl get pods -n auth
kubectl get services -n auth
kubectl get ingress -n auth
```

## Upgrade

### Update the deployment after code changes
```bash
# 1. Build and push new Docker image
docker build -t registry.digitalocean.com/cs464-project/gamification-service:latest .
docker push registry.digitalocean.com/cs464-project/gamification-service:latest

# 2. Restart pods to pull new image
kubectl rollout restart deployment gamification-service -n gamification

# Or upgrade via Helm
helm upgrade gamification-service . -n gamification
```

## Uninstall
```bash
helm uninstall gamification-service -n gamification
```

## Configuration

### Key Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Docker image repository | `registry.digitalocean.com/cs464-project/gamification-service` |
| `image.tag` | Docker image tag | `latest` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `ingress.enabled` | Enable ingress | `true` |
| `ingress.hosts` | Ingress hosts | `gamification.linyucong.com` |
| `postgresql.enabled` | Enable PostgreSQL subchart | `true` |
| `postgresql.auth.password` | PostgreSQL password | **Set in secrets file** |
| `autoscaling.enabled` | Enable HPA | `true` |
| `autoscaling.minReplicas` | Minimum replicas | `2` |
| `autoscaling.maxReplicas` | Maximum replicas | `10` |

### Custom values
Create a `values.secrets.yaml` file with your secrets (DO NOT COMMIT):
```yaml
image:
  tag: "v1.0.0"

postgresql:
  auth:
    password: "your-secure-password"

env:
  PGPASSWORD: "your-secure-password"
```

**Note:** RabbitMQ is disabled by default (`rabbitmq.enabled: false`). Only configure if you're using an external RabbitMQ service.

Then install with:
```bash
helm install gamification-service . \
  -f values.yaml \
  -f values.secrets.yaml \
  -n gamification
```

## Troubleshooting

### Check logs
```bash
# Check pod logs
kubectl logs -l app.kubernetes.io/name=gamification-service -n gamification

# Check specific pod logs
kubectl logs <pod-name> -n gamification

# Follow logs
kubectl logs -f -l app.kubernetes.io/name=gamification-service -n gamification
```

### Database issues

#### Missing column errors
The chart includes automatic migration that adds missing columns. If you see errors like:
```
ERROR: column "coin_price" of relation "tool_configs" does not exist
```

This is now automatically fixed by the migration code. The service will:
1. Check if the column exists
2. Add it if missing
3. Continue startup

#### Connection refused
If you see database connection errors, check:
```bash
# Check PostgreSQL is running
kubectl get pods -l app.kubernetes.io/name=postgresql -n gamification

# Check PostgreSQL logs
kubectl logs -l app.kubernetes.io/name=postgresql -n gamification

# Verify service
kubectl get svc gamification-postgresql -n gamification
```

The chart includes an init container that waits for PostgreSQL to be ready before starting the app.

### Pod not starting

#### Check events
```bash
kubectl describe pod <pod-name> -n gamification
```

#### Check readiness/liveness probes
The chart includes:
- **Startup probe**: Allows up to 150 seconds (30 failures × 5s) for app startup
- **Readiness probe**: Checks /health endpoint every 5 seconds
- **Liveness probe**: Checks /health endpoint every 10 seconds

### Image pull errors
```bash
# Verify image pull secret
kubectl get secret registry-cs464-project -n gamification

# If missing, create it
kubectl create secret docker-registry registry-cs464-project \
  --docker-server=registry.digitalocean.com \
  --docker-username=<your-username> \
  --docker-password=<your-token> \
  -n gamification
```

## Monitoring

### Health check
```bash
# Port forward to test locally
kubectl port-forward svc/gamification-service 8080:8080 -n gamification

# Test health endpoint
curl http://localhost:8080/health
```

### Swagger API docs
```bash
# Access via port forward
kubectl port-forward svc/gamification-service 8080:8080 -n gamification

# Open in browser
open http://localhost:8080/swagger/index.html
```

## Architecture

The deployment includes:
- **Application**: Gamification service (2+ replicas with HPA)
- **Database**: PostgreSQL (managed by subchart)
- **Init Container**: Waits for database availability
- **Probes**: Startup, readiness, and liveness checks
- **Ingress**: NGINX ingress with TLS/SSL
- **Auto-scaling**: HPA based on CPU/memory

## Security Notes

1. **Secrets**: Database passwords are stored in Kubernetes secrets
2. **TLS**: Ingress uses cert-manager for automatic SSL certificates
3. **Network**: ClusterIP service for internal communication only
4. **RBAC**: Consider adding service accounts and RBAC for production

## CI/CD Deployment (GitHub Actions)

The service is automatically deployed to DigitalOcean Kubernetes when pushing to `main` branch.

### Required GitHub Secrets

Go to: `Settings → Secrets and variables → Actions → New repository secret`

| Secret Name | Description | Where to get it |
|-------------|-------------|-----------------|
| `DIGITALOCEAN_ACCESS_TOKEN` | DigitalOcean API token | DigitalOcean → API → Tokens |
| `K8S_CLUSTER_NAME` | Kubernetes cluster name | DigitalOcean → Kubernetes → Cluster name |
| `REGISTRY_NAME` | Container registry URL | `registry.digitalocean.com/YOUR_REGISTRY` |
| `POSTGRESQL_PASSWORD` | Database password | Use a strong password generator |
| `CLOUDFLARE_ZONE_ID` | Cloudflare zone ID | Cloudflare → Domain → Zone ID |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token | Cloudflare → API Tokens → Edit DNS |

**Note:** Registry authentication uses the `DIGITALOCEAN_ACCESS_TOKEN` - no separate registry credentials needed!

### CD Pipeline Flow
1. ✅ Build Docker image with commit SHA tag
2. ✅ Push to DigitalOcean Container Registry
3. ✅ Connect to DigitalOcean Kubernetes cluster
4. ✅ Create/update Docker registry secret
5. ✅ Deploy with Helm (secrets injected from GitHub Secrets)
6. ✅ Verify deployment status
7. ✅ Get LoadBalancer IP address
8. ✅ Auto-update Cloudflare DNS (gamification.linyucong.com → LoadBalancer IP)

## Production Checklist

- [x] ~~Update default passwords in values.yaml~~ (Now use secrets file!)
- [x] Secrets stored securely in GitHub Actions
- [ ] Configure proper resource limits
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Configure backup for PostgreSQL
- [ ] Review and adjust HPA settings
- [ ] Set up proper DNS for ingress hostname
- [ ] Configure cert-manager for SSL certificates
- [ ] Review security policies
- [ ] Set up log aggregation
- [ ] Test disaster recovery procedures
