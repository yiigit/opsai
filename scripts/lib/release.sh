#!/usr/bin/env bash

OPSAI_REPOSITORY="${OPSAI_REPOSITORY:-yiigit/opsai}"
OPSAI_TEMP_DIR=""
OPSAI_CURL_CONFIG=""
OPSAI_ASSET_API_URL=""
OPSAI_ASSET_DOWNLOAD_URL=""

opsai_cleanup() {
    if [[ -n "$OPSAI_TEMP_DIR" ]]; then
        rm -rf -- "$OPSAI_TEMP_DIR"
    fi
}

opsai_die() {
    printf 'opsai installer: %s\n' "$*" >&2
    exit 1
}

opsai_prepare_release() {
    local token release_json release_data

    command -v curl >/dev/null 2>&1 || opsai_die 'curl is required.'
    command -v python3 >/dev/null 2>&1 || opsai_die 'Python 3 is required.'
    command -v dpkg >/dev/null 2>&1 || opsai_die 'dpkg is required (Ubuntu or Debian).'
    command -v apt-get >/dev/null 2>&1 || opsai_die 'apt-get is required (Ubuntu or Debian).'
    [[ "$OPSAI_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
        opsai_die 'OPSAI_REPOSITORY must be in OWNER/REPOSITORY format.'

    token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    [[ -n "$token" ]] || opsai_die 'Set GH_TOKEN or GITHUB_TOKEN with read access to the repository.'
    [[ "$token" =~ ^[A-Za-z0-9_]+$ ]] || opsai_die 'The GitHub token contains unsupported characters.'

    OPSAI_TEMP_DIR="$(mktemp -d)"
    trap opsai_cleanup EXIT
    OPSAI_CURL_CONFIG="$OPSAI_TEMP_DIR/curl.conf"
    chmod 600 "$OPSAI_TEMP_DIR"
    printf 'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\n' \
        "$token" > "$OPSAI_CURL_CONFIG"
    chmod 600 "$OPSAI_CURL_CONFIG"

    release_json="$OPSAI_TEMP_DIR/release.json"
    curl --config "$OPSAI_CURL_CONFIG" --fail --silent --show-error --location \
        --connect-timeout 15 --max-time 180 --retry 2 --retry-delay 1 \
        "https://api.github.com/repos/$OPSAI_REPOSITORY/releases/latest" \
        --output "$release_json" ||
        opsai_die "Could not read the latest release from $OPSAI_REPOSITORY."

    local python_minor architecture
    python_minor="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    architecture="$(dpkg --print-architecture)"
        release_data="$(python3 - "$release_json" "$python_minor" "$architecture" "$OPSAI_REPOSITORY" <<'PY'
    import json
    import re
    import sys
    from pathlib import Path

    release = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    tag = release.get("tag_name", "")
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
    if not match:
        raise SystemExit("Latest release has an invalid stable version tag.")
    version = ".".join(match.groups())
    python_minor, architecture, repository = sys.argv[2:]
    asset_name = f"opsai-cli_{version}_py{python_minor}_{architecture}.deb"
    for asset in release.get("assets", []):
        if asset.get("name") == asset_name:
            asset_id = asset.get("id")
            if not isinstance(asset_id, int) or asset_id <= 0:
                raise SystemExit("Release asset has an invalid identifier.")
            print(version)
            print(f"https://api.github.com/repos/{repository}/releases/assets/{asset_id}")
            break
    else:
    raise SystemExit(
        f"No Debian package found for Python {python_minor} / {architecture} "
        f"(expected {asset_name})."
    )
PY
    )" || opsai_die 'Could not find a compatible Debian package in the latest release.'

    IFS=$'\n' read -r OPSAI_VERSION OPSAI_DEB_URL <<< "$release_data"
    [[ -n "$OPSAI_VERSION" && -n "$OPSAI_DEB_URL" ]] ||
        opsai_die 'The latest release metadata is incomplete.'
    OPSAI_ASSET_API_URL="$OPSAI_DEB_URL"
}

opsai_download_release() {
    local destination="$1" headers asset_config
    headers="$OPSAI_TEMP_DIR/asset-headers"
    asset_config="$OPSAI_TEMP_DIR/asset-curl.conf"
    printf 'header = "Authorization: Bearer %s"\nheader = "Accept: application/octet-stream"\n' \
        "${GH_TOKEN:-${GITHUB_TOKEN:-}}" > "$asset_config"
    chmod 600 "$asset_config"

    curl --config "$asset_config" --silent --show-error \
        --connect-timeout 15 --max-time 60 \
        --dump-header "$headers" --output /dev/null "$OPSAI_ASSET_API_URL" ||
        opsai_die 'Could not request the private GitHub release asset.'

    OPSAI_ASSET_DOWNLOAD_URL="$(python3 - "$headers" <<'PY'
import sys
from pathlib import Path
from urllib.parse import urlparse

headers = Path(sys.argv[1]).read_text(encoding="iso-8859-1")
locations = [
    line.split(":", 1)[1].strip()
    for line in headers.splitlines()
    if line.lower().startswith("location:")
]
if not locations:
    raise SystemExit("GitHub did not redirect to a release asset.")
url = locations[-1]
parsed = urlparse(url)
if parsed.scheme != "https" or parsed.hostname not in {
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}:
    raise SystemExit("GitHub returned an untrusted release-asset URL.")
print(url)
PY
    )" || opsai_die 'GitHub returned an invalid release-asset URL.'

    curl --fail --silent --show-error --location \
        --connect-timeout 15 --max-time 180 --retry 2 --retry-delay 1 \
        "$OPSAI_ASSET_DOWNLOAD_URL" --output "$destination" ||
        opsai_die "Could not download OpsAI $OPSAI_VERSION."
}

opsai_as_root() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        opsai_die 'Run as root or install sudo to continue.'
    fi
}

opsai_debian_version() {
    printf '%s\n' "$1" | sed -E 's/\.dev([0-9]+)$/~dev\1/'
}
