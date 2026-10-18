#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/release.sh
source "$SCRIPT_DIR/scripts/lib/release.sh"

opsai_prepare_release
package="$OPSAI_TEMP_DIR/opsai.deb"
opsai_download_release "$package"
opsai_as_root apt-get install -y "$package"
printf 'Installed OpsAI %s.\n' "$OPSAI_VERSION"
