# syntax=docker/dockerfile:1.7
ARG APKTOOL_VERSION=2.12.1
FROM golang:1.26.10-trixie@sha256:909771fef53e3dcb0950255f0c9a8b4728c3b841e61509c7b29b098de7ee02d4 AS go-tools-builder
ARG GITLEAKS_VERSION=8.30.1
# Omit unused Syft Snap sources and ipsw IDA integrations.
ARG IPSW_VERSION=3.1.728
ARG SYFT_VERSION=1.52.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        fuse3 libfuse3-dev bzip2 libbz2-dev cmake libattr1-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 --branch "v${SYFT_VERSION}" \
        https://github.com/anchore/syft.git /tmp/syft \
    && cd /tmp/syft \
    && sed -i \
        -e '/"github.com\/anchore\/syft\/syft\/source\/snapsource"/d' \
        -e '/Join(tagProvider(snapsource[.]NewLocalSourceProvider/d' \
        -e '/Join(tagProvider(snapsource[.]NewRemoteSourceProvider/d' \
        -e '/Join(tagProvider(ocimodelsource/s/)[.]$/)/' \
        syft/source/sourceproviders/source_providers.go \
    && rm internal/file/getter.go \
    && gofmt -w syft/source/sourceproviders/source_providers.go \
    && go get github.com/containerd/containerd/v2@v2.3.6 \
        go.opentelemetry.io/otel/sdk@v1.45.0 golang.org/x/net@v0.60.0 \
        github.com/moby/sys/user@v0.4.1 \
    && CGO_ENABLED=0 go list -deps ./cmd/syft > /tmp/syft-deps.txt \
    && ! grep -E '^github[.]com/hashicorp/go-getter(/|$)' /tmp/syft-deps.txt \
    && CGO_ENABLED=0 go build -ldflags "-X main.version=${SYFT_VERSION}" \
        -o /go/bin/syft ./cmd/syft \
    && go version -m /go/bin/syft > /tmp/syft-build-info.txt \
    && ! grep -F 'github.com/hashicorp/go-getter' /tmp/syft-build-info.txt \
    && git clone --depth 1 --branch "v${GITLEAKS_VERSION}" \
        https://github.com/gitleaks/gitleaks.git /tmp/gitleaks \
    && cd /tmp/gitleaks \
    && go get golang.org/x/crypto@v0.56.0 \
        github.com/mholt/archives@v0.1.5 \
        github.com/klauspost/compress@v1.18.7 \
        github.com/nwaples/rardecode/v2@v2.2.0 github.com/ulikunitz/xz@v0.5.15 \
    && go build -ldflags "-X=github.com/zricethezav/gitleaks/v8/version.Version=v${GITLEAKS_VERSION}" \
        -o /go/bin/gitleaks . \
    && git clone --depth 1 --branch "v${IPSW_VERSION}" \
        https://github.com/blacktop/ipsw.git /tmp/ipsw \
    && cd /tmp/ipsw \
    && rm cmd/ipsw/cmd/dyld/dyld_ida.go cmd/ipsw/cmd/kernel/kernel_ida.go \
    && go get google.golang.org/grpc@v1.83.2 github.com/antchfx/xpath@v1.3.6 \
        golang.org/x/net@v0.60.0 \
    && go list -deps ./cmd/ipsw > /tmp/ipsw-deps.txt \
    && ! grep -E '^github[.]com/docker/docker(/|$)' /tmp/ipsw-deps.txt \
    && CGO_ENABLED=1 go build \
        -ldflags "-s -w -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=v${IPSW_VERSION}" \
        -o /go/bin/ipsw ./cmd/ipsw \
    && go version -m /go/bin/ipsw > /tmp/ipsw-build-info.txt \
    && ! grep -F 'github.com/docker/docker' /tmp/ipsw-build-info.txt

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:824f77df45397eb954dfb963db255907ee8842e3446353ce93d688e5e862f51d AS java-runtime-builder
# APKTool needs image processing; native audio and X11 backends are unused.
RUN apk add --no-cache binutils openjdk-21=21.0.12.1-r4 openjdk-21-jmods=21.0.12.1-r4 \
    && /usr/lib/jvm/java-21-openjdk/bin/jlink \
        --add-modules java.base,java.desktop,java.logging,jdk.crypto.ec,jdk.unsupported,jdk.zipfs \
        --strip-debug --no-header-files --no-man-pages \
        --exclude-files '**/libjsound.so,**/libawt_xawt.so' \
        --output /opt/phoenix-java

FROM java-runtime-builder AS apktool-builder
ARG APKTOOL_VERSION
ARG GUAVA_VERSION=33.7.2-jre
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
# Rebuild the pinned release with Guava's deserialization fix.
RUN apk add --no-cache git \
    && git clone --depth 1 --branch "v${APKTOOL_VERSION}" \
        https://github.com/iBotPeaches/Apktool.git /tmp/apktool \
    && cd /tmp/apktool \
    && sed -i "s/^guava = \".*\"$/guava = \"${GUAVA_VERSION}\"/" gradle/libs.versions.toml \
    && ./gradlew --no-daemon --max-workers=2 release :brut.apktool:apktool-cli:proguard -x test \
    && cp "brut.apktool/apktool-cli/build/libs/apktool-${APKTOOL_VERSION}.jar" /tmp/apktool.jar

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
    SYFT_CHECK_FOR_APP_UPDATE=false \
    TRUFFLEHOG_NO_UPDATE=1

# 2. System dependencies
ARG TARGETARCH
# Google's Linux Android tools match the linux/amd64 image published by CI.
RUN test "${TARGETARCH:-amd64}" = amd64 \
    || { echo "Android SDK Build Tools require --platform linux/amd64" >&2; exit 1; }
RUN apk upgrade --no-cache \
    && apk add --no-cache \
        "glibc-2.44>=2.44-r8" "glibc-2.44-locale-posix>=2.44-r8" \
        "ld-linux-2.44>=2.44-r8" "libcrypt1-2.44>=2.44-r8" \
        python-3.15=3.15.0-r0 \
        "openssl-4.0-libcrypto>=4.0.3-r2" \
        "libbrotlicommon1>=1.2.1-r0" "libbrotlidec1>=1.2.1-r0" "libbrotlienc1>=1.2.1-r0" \
        bash git curl "ca-certificates-bundle>=20260909-r3" \
        binutils libmagic \
        pango harfbuzz ttf-dejavu lcms2 libjpeg-turbo

COPY --from=java-runtime-builder /opt/phoenix-java /usr/lib/jvm/java-21-openjdk

# Wolfi has no aapt package; retain aapt2 and apksigner from Google's Build Tools 36.1.
ARG ANDROID_BUILD_TOOLS_ARCHIVE=build-tools_r36.1_linux.zip
ARG ANDROID_BUILD_TOOLS_SHA256=a7b5889e4a79fcf3b0976bef40d401f4240fb1eed891d9d91169da1111e11d78
RUN <<'SH'
set -eu
curl -sSfL "https://dl.google.com/android/repository/${ANDROID_BUILD_TOOLS_ARCHIVE}" -o /tmp/android-build-tools.zip
echo "${ANDROID_BUILD_TOOLS_SHA256}  /tmp/android-build-tools.zip" | sha256sum -c -
python3.15 - <<'PY'
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
ARG APKTOOL_VERSION
COPY --from=apktool-builder /tmp/apktool.jar /usr/local/bin/apktool.jar
RUN curl -sSfL "https://raw.githubusercontent.com/trufflesecurity/trufflehog/${TRUFFLEHOG_VERSION}/scripts/install.sh" | sh -s -- -b /usr/local/bin "${TRUFFLEHOG_VERSION}" \
    && curl -sSfL -o /usr/local/bin/apktool \
    "https://raw.githubusercontent.com/iBotPeaches/Apktool/v${APKTOOL_VERSION}/scripts/linux/apktool" \
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
ARG LIEF_VERSION=1.0.0
ARG BROTLI_VERSION=1.2.1
ARG OPENGREP_VERSION=1.30.0
RUN apk add --no-cache --virtual .python-build-deps \
        build-base python-3.15-dev=3.15.0-r0 \
    && python3.15 -m venv /opt/phoenix-venv \
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
        "brotli==${BROTLI_VERSION}" \
    && opengrep --version \
    && /opt/phoenix-venv/bin/python -c "from importlib.metadata import version; print('apkid ' + version('apkid'))" \
    && /opt/phoenix-venv/bin/python -c "from androguard.misc import AnalyzeAPK; import lief; print('androguard and lief imports ok')" \
    && apk del .python-build-deps

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
    && apk del curl \
    && /opt/phoenix-venv/bin/python -m pip uninstall --yes pip

# 6. Working Directory
USER phoenix
WORKDIR /workspace

ENTRYPOINT ["/bin/bash"]
