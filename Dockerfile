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

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:824f77df45397eb954dfb963db255907ee8842e3446353ce93d688e5e862f51d AS phoenix

LABEL org.opencontainers.image.source="https://github.com/Blue-Milk-Apps/Phoenix-MAST"

# 1. Environment & Global Settings
ENV FORCE_COLOR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHOENIX_RULES_ROOT=/app/rules \
    JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
    PATH="/opt/phoenix-venv/bin:/usr/local/bin:/usr/lib/jvm/java-21-openjdk/bin:$PATH" \
    OPENGREP_OFFLINE=1 \
    OPENGREP_DISABLE_METRICS=1 \
    OPENGREP_SEND_METRICS=off \
    TRUFFLEHOG_NO_UPDATE=1

# 2. System dependencies
ARG TARGETARCH
# Google's Linux Android tools match the linux/amd64 image published by CI.
RUN test "${TARGETARCH:-amd64}" = amd64 \
    || { echo "Android SDK Build Tools require --platform linux/amd64" >&2; exit 1; }
RUN apk upgrade --no-cache \
    && apk add --no-cache \
        python-3.12 py3.12-pip \
        bash git curl ca-certificates-bundle \
        binutils libmagic \
        pango harfbuzz ttf-dejavu \
        openjdk-21-jre

# Wolfi has no aapt package; retain aapt2 and apksigner from Google's Build Tools 36.1.
ARG ANDROID_BUILD_TOOLS_ARCHIVE=build-tools_r36.1_linux.zip
ARG ANDROID_BUILD_TOOLS_SHA256=a7b5889e4a79fcf3b0976bef40d401f4240fb1eed891d9d91169da1111e11d78
RUN <<'SH'
set -eu
curl -sSfL "https://dl.google.com/android/repository/${ANDROID_BUILD_TOOLS_ARCHIVE}" -o /tmp/android-build-tools.zip
echo "${ANDROID_BUILD_TOOLS_SHA256}  /tmp/android-build-tools.zip" | sha256sum -c -
python3.12 - <<'PY'
from pathlib import Path
from zipfile import ZipFile

destination = Path("/opt/android-build-tools")
with ZipFile("/tmp/android-build-tools.zip") as archive:
    source = Path(next(name for name in archive.namelist() if name.endswith("/aapt2"))).parent
    for name in ("aapt2", "apksigner", "lib/apksigner.jar", "NOTICE.txt", "source.properties"):
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive.read(str(source / name)))
        target.chmod(0o755 if name in ("aapt2", "apksigner") else 0o644)
PY
mkdir -p /usr/local/bin
ln -s /opt/android-build-tools/aapt2 /usr/local/bin/aapt2
ln -s /opt/android-build-tools/apksigner /usr/local/bin/apksigner
rm /tmp/android-build-tools.zip
SH

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
RUN python3.12 -m venv /opt/phoenix-venv \
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
RUN addgroup -g 1001 phoenix \
    && adduser -D -u 1001 -G phoenix phoenix \
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
    && apk del curl py3.12-pip \
    && /opt/phoenix-venv/bin/python -m pip uninstall --yes pip

# 6. Working Directory
USER phoenix
WORKDIR /workspace

ENTRYPOINT ["/bin/bash"]
