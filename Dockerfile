# syntax=docker/dockerfile:1.7
FROM golang:1.26.6-trixie@sha256:b75d466dd608587fd66cca705a307ba65b889827d06ad61d6a75f0482b51b7c7 AS go-tools-builder
ARG GITLEAKS_VERSION=8.30.1
ARG IPSW_VERSION=3.1.728
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        fuse3 libfuse3-dev bzip2 libbz2-dev cmake libattr1-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* \
    && go install github.com/anchore/syft/cmd/syft@v1.52.0 \
    && git clone --depth 1 --branch "v${GITLEAKS_VERSION}" \
        https://github.com/gitleaks/gitleaks.git /tmp/gitleaks \
    && cd /tmp/gitleaks \
    && go get golang.org/x/crypto@v0.56.0 \
    && go build -ldflags "-X=github.com/zricethezav/gitleaks/v8/version.Version=v${GITLEAKS_VERSION}" \
        -o /go/bin/gitleaks . \
    && git clone --depth 1 --branch "v${IPSW_VERSION}" \
        https://github.com/blacktop/ipsw.git /tmp/ipsw \
    && cd /tmp/ipsw \
    && go get google.golang.org/grpc@v1.83.2 \
    && CGO_ENABLED=1 go build \
        -ldflags "-s -w -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=v${IPSW_VERSION}" \
        -o /go/bin/ipsw ./cmd/ipsw

FROM python:3.12-slim-trixie AS phoenix

LABEL org.opencontainers.image.source="https://github.com/Blue-Milk-Apps/Phoenix-MAST"

# 1. Environment & Global Settings
ENV DEBIAN_FRONTEND=noninteractive \
    FORCE_COLOR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHOENIX_RULES_ROOT=/app/rules \
    PATH="/opt/phoenix-venv/bin:/usr/local/bin:$PATH" \
    OPENGREP_OFFLINE=1 \
    OPENGREP_DISABLE_METRICS=1 \
    OPENGREP_SEND_METRICS=off \
    TRUFFLEHOG_NO_UPDATE=1

# 2. System dependencies
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
    bash git curl ca-certificates \
    aapt apksigner \
    binutils libmagic1t64 \
    libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
    openjdk-21-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# 3. Static Tooling Installations
ARG TRUFFLEHOG_VERSION=v3.97.9
ARG APKTOOL_VERSION=2.10.0
RUN curl -sSfL "https://raw.githubusercontent.com/trufflesecurity/trufflehog/${TRUFFLEHOG_VERSION}/scripts/install.sh" | sh -s -- -b /usr/local/bin "${TRUFFLEHOG_VERSION}" \
    && curl -sSfL -o /usr/local/bin/apktool \
    "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
    && curl -sSfL -o /usr/local/bin/apktool.jar \
    "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    && chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar \
    && apktool --version \
    && aapt2 version \
    && apksigner version \
    && trufflehog --version

COPY --from=go-tools-builder /go/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=go-tools-builder /go/bin/ipsw /usr/local/bin/ipsw
COPY --from=go-tools-builder /go/bin/syft /usr/local/bin/syft
RUN gitleaks version && ipsw version && syft version

# 4. Python Environment Setup
ARG APKID_VERSION=3.1.0
ARG ANDROGUARD_VERSION=4.1.4
ARG LIEF_VERSION=0.17.6
ARG OPENGREP_VERSION=1.30.0
ARG TARGETARCH
RUN /usr/local/bin/python -m pip install --no-cache-dir --upgrade "pip>=26.2.0" \
    && /usr/local/bin/python -m venv /opt/phoenix-venv \
    && /opt/phoenix-venv/bin/python -m pip install --no-cache-dir --upgrade "pip>=26.2.0" \
    && case "${TARGETARCH:-amd64}" in \
        amd64) OPENGREP_ASSET="opengrep_manylinux_x86" ;; \
        arm64) OPENGREP_ASSET="opengrep_manylinux_aarch64" ;; \
        *) echo "Unsupported OpenGrep Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -sSfL \
        "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${OPENGREP_ASSET}" \
        -o /usr/local/bin/opengrep \
    && chmod +x /usr/local/bin/opengrep \
    && ln -sf /usr/local/bin/opengrep /usr/local/bin/opengrep-core \
    && /opt/phoenix-venv/bin/pip install --no-cache-dir \
        "androguard==${ANDROGUARD_VERSION}" \
        "lief==${LIEF_VERSION}" \
        "apkid==${APKID_VERSION}" \
    && opengrep --version \
    && /opt/phoenix-venv/bin/python -c "from importlib.metadata import version; print('apkid ' + version('apkid'))" \
    && /opt/phoenix-venv/bin/python -c "from androguard.misc import AnalyzeAPK; import lief; print('androguard and lief imports ok')"

# 5. Application User and Source Code
WORKDIR /app
RUN useradd -m -u 1001 phoenix \
    && install -d -o phoenix -g phoenix /app/rules

COPY --chown=phoenix:phoenix README.md pyproject.toml ./
COPY --chown=phoenix:phoenix __init__.py ./
COPY --chown=phoenix:phoenix utilities ./utilities
COPY --chown=phoenix:phoenix adapters ./adapters
COPY --chown=phoenix:phoenix application ./application
COPY --chown=phoenix:phoenix domain ./domain
COPY --chown=phoenix:phoenix entrypoints ./entrypoints
COPY --chown=phoenix:phoenix ports ./ports

RUN /opt/phoenix-venv/bin/pip install --no-cache-dir . \
    && apt-get purge -y curl \
    && apt-get autoremove --purge -y \
    && /opt/phoenix-venv/bin/python -m pip uninstall --yes pip \
    && /usr/local/bin/python -m pip uninstall --yes pip \
    && rm -rf /var/lib/apt/lists/*

# 6. Working Directory
USER phoenix
WORKDIR /workspace

ENTRYPOINT ["/bin/bash"]
