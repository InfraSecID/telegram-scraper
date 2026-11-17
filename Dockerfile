# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS deps

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production \
    SECURITY_NUCLEI_TEMPLATES=/opt/nuclei-templates

# Versi tool dipin agar build reproducible. Perbarui manual setelah diuji.
ARG TARGETARCH=amd64
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.12.0
ARG KATANA_VERSION=v1.8.0
ARG SUBFINDER_VERSION=v2.17.0
ARG DALFOX_VERSION=v3.3.0
ARG SQLMAP_TAG=1.10
ARG PARAMSPIDER_TAG=v1.0.1
ARG NUCLEI_TEMPLATES_TAG=v10.5.2

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    python3 \
    python3-venv \
    unzip \
  && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery tools (nuclei, httpx, katana, subfinder).
RUN set -eux; \
  arch="${TARGETARCH:-amd64}"; \
  case "$arch" in amd64|arm64) ;; *) echo "Arsitektur tidak didukung: $arch" >&2; exit 1 ;; esac; \
  install_pd() { \
    repo="$1"; version="$2"; binary="$3"; ver="${version#v}"; \
    curl -fsSL --retry 3 -o /tmp/tool.zip \
      "https://github.com/projectdiscovery/${repo}/releases/download/${version}/${repo}_${ver}_linux_${arch}.zip"; \
    unzip -oq /tmp/tool.zip -d /tmp/tool; \
    install -m 0755 "/tmp/tool/${binary}" "/usr/local/bin/${binary}"; \
    rm -rf /tmp/tool /tmp/tool.zip; \
  }; \
  install_pd nuclei "$NUCLEI_VERSION" nuclei; \
  install_pd httpx "$HTTPX_VERSION" httpx; \
  install_pd katana "$KATANA_VERSION" katana; \
  install_pd subfinder "$SUBFINDER_VERSION" subfinder

# dalfox (XSS scanner).
RUN set -eux; \
  arch="${TARGETARCH:-amd64}"; \
  case "$arch" in \
    amd64) dalfox_arch="x86_64" ;; \
    arm64) dalfox_arch="aarch64" ;; \
    *) echo "Arsitektur tidak didukung: $arch" >&2; exit 1 ;; \
  esac; \
  curl -fsSL --retry 3 -o /tmp/dalfox.tar.gz \
    "https://github.com/hahwul/dalfox/releases/download/${DALFOX_VERSION}/dalfox-${DALFOX_VERSION}-linux-${dalfox_arch}-musl.tar.gz"; \
  mkdir -p /tmp/dalfox; \
  tar -xzf /tmp/dalfox.tar.gz -C /tmp/dalfox; \
  find /tmp/dalfox -type f -name dalfox -exec install -m 0755 {} /usr/local/bin/dalfox \; ; \
  rm -rf /tmp/dalfox /tmp/dalfox.tar.gz

# sqlmap (SQL injection, mode deteksi) dan ParamSpider (penemuan parameter).
RUN set -eux; \
  git clone --depth 1 --branch "${SQLMAP_TAG}" https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap; \
  printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap; \
  chmod +x /usr/local/bin/sqlmap; \
  git clone --depth 1 --branch "${PARAMSPIDER_TAG}" https://github.com/devanshbatham/ParamSpider.git /opt/ParamSpider; \
  python3 -m venv /opt/paramspider-venv; \
  /opt/paramspider-venv/bin/pip install --no-cache-dir /opt/ParamSpider; \
  ln -sf /opt/paramspider-venv/bin/paramspider /usr/local/bin/paramspider

# Template nuclei resmi (dipin) agar scan tidak bergantung update saat runtime.
RUN set -eux; \
  curl -fsSL --retry 3 -o /tmp/nuclei-templates.tar.gz \
    "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_TAG}.tar.gz"; \
  tar -xzf /tmp/nuclei-templates.tar.gz -C /opt; \
  mv "/opt/nuclei-templates-${NUCLEI_TEMPLATES_TAG#v}" /opt/nuclei-templates; \
  chmod -R a+rX /opt/nuclei-templates; \
  rm -f /tmp/nuclei-templates.tar.gz

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY config ./config
COPY docs ./docs

RUN mkdir -p /app/data && chown -R node:node /app

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/index.js"]
