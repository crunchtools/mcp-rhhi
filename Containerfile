# MCP RHHI CrunchTools Container
# Built on the Hummingbird Python image it catalogs
#
# Build:
#   podman build -t quay.io/crunchtools/mcp-rhhi .
#
# Run:
#   podman run -i --rm quay.io/crunchtools/mcp-rhhi
#
# With Claude Code:
#   claude mcp add mcp-rhhi-crunchtools -- podman run -i --rm quay.io/crunchtools/mcp-rhhi

# Stage 1: Builder (has shell, dnf, build tools)
FROM quay.io/hummingbird/python:3.14-builder AS builder
USER 0
WORKDIR /app
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# Stage 2: Runtime (distroless — no shell, no package manager)
FROM quay.io/hummingbird/python:3.14

LABEL name="mcp-rhhi-crunchtools" \
      version="0.1.0" \
      summary="Read-only MCP server for the Hummingbird / Red Hat Hardened Images catalog" \
      description="Images, tags, container config, SBOMs and CVEs from the Hummingbird catalog API" \
      maintainer="crunchtools.com" \
      url="https://github.com/crunchtools/mcp-rhhi" \
      io.k8s.display-name="MCP RHHI CrunchTools" \
      io.openshift.tags="mcp,hummingbird,rhhi,sbom,cve" \
      org.opencontainers.image.source="https://github.com/crunchtools/mcp-rhhi" \
      org.opencontainers.image.description="Read-only MCP server for the Hummingbird / Red Hat Hardened Images catalog" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

COPY --from=builder /app/venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Verify installation. Exec form, since this stage has no /bin/sh for RUN's shell form.
RUN ["python3", "-c", "from mcp_rhhi_crunchtools import main; print('Installation verified')"]

# Default: stdio transport (use -i with podman run)
# HTTP:    --transport streamable-http (use -d -p 8030:8030 with podman run)
EXPOSE 8030
ENTRYPOINT ["python", "-m", "mcp_rhhi_crunchtools"]
