# Container vulnerability verification

The Dockerfile pins Wolfi's patched Python 3.14 maintenance build,
`3.14.8_git20261001-r2`. The older released `3.14.7-r8` package retains
`CVE-2026-19672` in both Python APK packages. The engine still supports Python
3.12+; the container runtime is upgraded independently.

## Docker dependency assessment

`phoenix.openvex.json` records `not_affected` only for the assessed image and
its `github.com/docker/docker@v28.5.2+incompatible` dependency inside ipsw.
It does not declare that dependency safe in other applications or assess
the Docker daemon used to run Phoenix.

The assessed ipsw 3.1.728 executable has SHA-256
`e670464829ba97030cc1d1e1722874a6cb309c0c7fe8e8ac1f092af509c26508`.
Inspection of its Go function table found 101,630 functions, including 64
Docker client functions and zero functions from `github.com/docker/docker/daemon`,
`github.com/docker/docker/pkg/authorization`, or `github.com/docker/docker/plugin`.
`go list -deps ./cmd/ipsw` in the Dockerfile's builder also excludes those
packages. The Docker imports are API types, the client, and `pkg/stdcopy`.

The assessed advisories concern daemon code:

- [AuthZ plugin bypass](https://github.com/moby/moby/security/advisories/GHSA-x744-4wpc-v9h2): `GO-2026-4887`.
- [Plugin privilege validation](https://github.com/moby/moby/security/advisories/GHSA-pxq6-2prw-chj9): `GHSA-pxq6-2prw-chj9`.
- [Archive decompression on the host](https://github.com/moby/moby/security/advisories/GHSA-x86f-5xw2-fm2r): `GHSA-x86f-5xw2-fm2r`.
- [Bind mount redirection](https://github.com/moby/moby/security/advisories/GHSA-rg2x-37c3-w2rh): `GHSA-rg2x-37c3-w2rh`.
- [Host file creation](https://github.com/moby/moby/security/advisories/GHSA-vp62-88p7-qqf5): `GHSA-vp62-88p7-qqf5`.

## Scan with the scoped assessment

Build and scan the archive first, preserving the unfiltered results:

```bash
docker buildx build --platform linux/amd64 --progress plain \
  --output type=docker,dest=/tmp/phoenix-security-python314.tar \
  -t phoenix:security-python314 .
grype docker-archive:/tmp/phoenix-security-python314.tar \
  -o json --file /tmp/phoenix-security-python314.json
```

Grype's OpenVEX matcher does not use a local archive's config digest as an
image product identifier. Generate an SBOM using the included Syft, with
the scanned image ID as its source version. Load that same archive before
generating the inventory, and retain the raw archive report as provenance:

```bash
docker load -i /tmp/phoenix-security-python314.tar
phoenix_image_version=$(python3 -c 'import json; print(json.load(open("/tmp/phoenix-security-python314.json"))["source"]["target"]["imageID"])')
docker run --rm --pull=never --platform linux/amd64 --network none \
  --entrypoint syft phoenix:security-python314 scan dir:/ \
  --override-default-catalogers image --source-name phoenix \
  --source-version "$phoenix_image_version" -o syft-json \
  > /tmp/phoenix-python314.syft.json
grype sbom:/tmp/phoenix-python314.syft.json \
  --vex setup/container/phoenix.openvex.json --fail-on medium \
  -o json --file /tmp/phoenix-python314-reviewed.json
```

The SBOM scan may report additional matches because it cannot inspect the
binary directly as an archive scan can. The VEX covers the five verified
daemon advisories; other findings remain visible, including Unknown findings.

The document is bound to one image ID. After a rebuild produces a different
ID, recheck the ipsw executable and dependency list, then issue a new assessment.
Do not assign an old image ID to a new SBOM to make the document match.

Python, glibc, and ALSA findings are not suppressed. A Medium-or-higher gate
continues to fail until those findings are patched or separately resolved
with evidence.
