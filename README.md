# vsb

Release builds of the VorPilot Server container images and Helm charts.

Each release starts as a draft carrying pre-built binaries and chart packages.
When its tag lands on `main`, the workflow builds the images, scans them, checks
the charts, publishes both to GitHub Container Registry under the release
version and signs them:

- `ghcr.io/vortilis/vorpilot-scout`, `ghcr.io/vortilis/vorpilot-frontend` —
  Server Standard and Pro
- `ghcr.io/vortilis/vorpilot-scout-ce`, `ghcr.io/vortilis/vorpilot-frontend-ce` —
  Server CE, the open-source build (`scout.ce: true` in the server chart)
- `oci://ghcr.io/vortilis/charts/vorpilot-server`
- `oci://ghcr.io/vortilis/charts/vorpilot-agent`
- `oci://ghcr.io/vortilis/charts/vorpilot-rbac-bootstrap`

This repository holds no source code, and its files are managed elsewhere —
changes made here are overwritten.
