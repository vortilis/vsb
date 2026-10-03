# vsb

Release builds of the VorPilot Server container images.

Each release starts as a draft carrying pre-built binaries. When its tag lands on
`main`, the workflow builds the images, scans them, publishes them to GitHub
Container Registry and signs them:

- `ghcr.io/vortilis/vorpilot-scout`
- `ghcr.io/vortilis/vorpilot-frontend`

This repository holds no source code, and its files are managed elsewhere —
changes made here are overwritten.
