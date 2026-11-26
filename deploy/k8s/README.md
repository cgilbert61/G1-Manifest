# G1-Manifest Kubernetes Deployment

Apply the base manifests in `k8s/` or deploy via the Helm chart in `deploy/helm/g1-manifest/` (mirrored in `charts/g1-manifest/`):

```bash
kubectl apply -f k8s/
# or
helm install g1-manifest deploy/helm/g1-manifest/
```
