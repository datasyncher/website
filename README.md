# Datasyncher marketing website

Static Next.js export served at the **root** of the public host (e.g. `https://gcp.datasyncher.com/`), alongside the product UI (`/auth/`, `/dashboard/`) and customer docs (`/docs/`).

## Repository layout

| Path | Purpose |
|------|---------|
| `site/` | Pre-built static export (`index.html`, `/_next/`, `/platform/`, …) |
| `demo-config.example.php` | Template for contact/demo forms (Apache + PHP hosts only) |

## Updating content

1. Generate a new static export from the Next.js website source (see internal website repo).
2. Replace contents of `site/` (keep `demo-config.example.php` at repo root).
3. Push to `main`; roll out on GKE via `Datasyncher-React-Adapter/k8s/batch-cluster/rollout-website-batch.ps1 -Build`.

## PHP contact forms

Production **datasyncher.com** uses Apache, PHP 8, and `demo.php` (see `site/DEPLOY.txt` in the bundle). **GKE batch** currently ships **nginx static only** — marketing pages work; demo/contact forms need a follow-up PHP image or an external form handler.

Never commit `site/demo-config.php` (contains secrets). Use `demo-config.example.php`.

## Related

- Customer docs: [datasyncher/documentation](https://github.com/datasyncher/documentation)
- Batch rollout: `rollout-website-batch.ps1` in `Datasyncher-React-Adapter`