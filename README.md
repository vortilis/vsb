# vsb

Release builds of the VorPilot Server container images and Helm charts.

Each release starts as a draft carrying pre-built binaries and chart packages.
When its tag lands on `main`, the workflow builds the images, scans them, checks
the charts, publishes both to GitHub Container Registry under the release
version and signs them:

- `ghcr.io/vortilis/vorpilot-scout`, `ghcr.io/vortilis/vorpilot-frontend` —
  Server Standard and Pro
- `oci://ghcr.io/vortilis/charts/vorpilot-server`
- `oci://ghcr.io/vortilis/charts/vorpilot-agent`
- `oci://ghcr.io/vortilis/charts/vorpilot-rbac-bootstrap`

Server CE, the open-source build, is released separately under the same
version.

This repository holds no source code, and its files are managed elsewhere —
changes made here are overwritten.
