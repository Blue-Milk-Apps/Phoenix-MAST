# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm AS phoenix

LABEL org.opencontainers.image.source="https://github.com/Blue-Milk-Apps/phoenix"

# 1. Environment & Global Settings
ENV DEBIAN_FRONTEND=noninteractive \
    FORCE_COLOR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/phoenix-venv/bin:/usr/local/bin:$PATH" \
    OPENGREP_OFFLINE=1 \
    OPENGREP_DISABLE_METRICS=1 \
    OPENGREP_SEND_METRICS=off \
    DC_NO_UPDATE=1 \
    TRUFFLEHOG_NO_UPDATE=1

# 2. System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash git curl wget unzip jq ca-certificates \
    apksigner \
    binutils libmagic1 \
    openjdk-17-jdk \
    && rm -rf /var/lib/apt/lists/*

# 3. Static Tooling Installations
ARG SYFT_VERSION=v1.44.0
ARG TRUFFLEHOG_VERSION=v3.95.2
ARG GITLEAKS_VERSION=8.30.1
ARG APKTOOL_VERSION=2.10.0
ARG IPSW_VERSION=3.1.687
RUN curl -sSfL "https://raw.githubusercontent.com/anchore/syft/${SYFT_VERSION}/install.sh" | sh -s -- -b /usr/local/bin "${SYFT_VERSION}" \
    && curl -sSfL "https://raw.githubusercontent.com/trufflesecurity/trufflehog/${TRUFFLEHOG_VERSION}/scripts/install.sh" | sh -s -- -b /usr/local/bin "${TRUFFLEHOG_VERSION}" \
    && curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
    && curl -sSfL "https://github.com/blacktop/ipsw/releases/download/v${IPSW_VERSION}/ipsw_${IPSW_VERSION}_linux_x86_64.tar.gz" \
    | tar -xz -C /usr/local/bin ipsw \
    && curl -sSfL -o /usr/local/bin/apktool \
    "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
    && curl -sSfL -o /usr/local/bin/apktool.jar \
    "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    && chmod +x /usr/local/bin/gitleaks /usr/local/bin/ipsw /usr/local/bin/apktool /usr/local/bin/apktool.jar \
    && apktool --version \
    && apksigner version \
    && gitleaks version \
    && ipsw version \
    && syft version \
    && trufflehog --version

# 4. OWASP Dependency Check
ARG DEPENDENCY_CHECK_VERSION=12.2.0
ENV DC_NO_UPDATE=1
RUN wget -q -L "https://github.com/dependency-check/DependencyCheck/releases/download/v${DEPENDENCY_CHECK_VERSION}/dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip" \
    && unzip -q "dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip" -d /opt \
    && rm "dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip" \
    && ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check \
    && chmod +x /opt/dependency-check/bin/dependency-check.sh \
    && mkdir -p /opt/dependency-check/data \
    && dependency-check --version

# 5. Python Environment Setup
ARG APKID_VERSION=3.1.0
ARG ANDROGUARD_VERSION=4.1.3
ARG LIEF_VERSION=0.17.2
ARG OPENGREP_VERSION=1.22.0
ARG TARGETARCH
RUN python -m venv /opt/phoenix-venv \
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

# 6. Copy Modular Source Code
WORKDIR /app
COPY README.md pyproject.toml ./
COPY __init__.py ./
COPY utilities ./utilities
COPY adapters ./adapters
COPY application ./application
COPY domain ./domain
COPY entrypoints ./entrypoints
COPY ports ./ports
COPY rules ./rules

RUN /opt/phoenix-venv/bin/pip install --no-cache-dir .

# 7. Permissions & Working Dir
# We need to ensure the 'phoenix' user owns the data mount point
# so it can create the H2 database lock files.
RUN useradd -m -u 1001 phoenix \
    && mkdir -p /opt/dependency-check/data \
    && chown -R phoenix:phoenix /app /opt/dependency-check /opt/phoenix-venv /usr/local/bin/opengrep

USER phoenix
WORKDIR /workspace

ENTRYPOINT ["phoenix"]
CMD ["--help"]
