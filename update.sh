#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/release.sh
source "$SCRIPT_DIR/scripts/lib/release.sh"

command -v opsai >/dev/null 2>&1 || opsai_die 'OpsAI is not installed; use install.sh first.'
current_version="$(opsai --version | awk '{print $3}')"
[[ "$current_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(\.dev[0-9]+)?$ ]] ||
    opsai_die 'Could not determine the installed OpsAI version.'

opsai_prepare_release
current_debian_version="$(opsai_debian_version "$current_version")"
latest_debian_version="$(opsai_debian_version "$OPSAI_VERSION")"
if dpkg --compare-versions "$latest_debian_version" le "$current_debian_version"; then
    printf 'OpsAI %s is already current (latest release: %s).\n' "$current_version" "$OPSAI_VERSION"
    exit 0
fi

package="$OPSAI_TEMP_DIR/opsai.deb"
opsai_download_release "$package"
opsai_as_root apt-get install -y "$package"
printf 'Updated OpsAI from %s to %s.\n' "$current_version" "$OPSAI_VERSION"
