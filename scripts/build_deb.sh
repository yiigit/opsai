#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 1 || ! -f "$1" ]]; then
    printf 'Usage: %s PATH_TO_OPSAI_WHEEL\n' "$0" >&2
    exit 2
fi

wheel="$(realpath "$1")"
python="${PYTHON:-python3}"
command -v dpkg-deb >/dev/null 2>&1 || {
    printf 'build_deb.sh: dpkg-deb is required.\n' >&2
    exit 1
}

version="$("$python" - "$wheel" <<'PY'
import sys
from packaging.utils import parse_wheel_filename

name, version, _, _ = parse_wheel_filename(sys.argv[1].rsplit("/", 1)[-1])
if name != "opsai-cli":
    raise SystemExit("Expected an opsai-cli wheel.")
print(version)
PY
)"
python_minor="$("$python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
python_major="${python_minor%%.*}"
python_patch="${python_minor##*.}"
next_minor="$((python_patch + 1))"
architecture="$(dpkg --print-architecture)"
debian_version="$(printf '%s\n' "$version" | sed -E 's/\.dev([0-9]+)$/~dev\1/')"
output_dir="${2:-dist}"
output_dir="$(mkdir -p "$output_dir" && cd "$output_dir" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf -- "$stage"' EXIT

site_packages="$stage/usr/lib/opsai/python$python_minor"
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$site_packages"
"$python" -m pip install --disable-pip-version-check --no-compile \
    --no-warn-script-location --only-binary=:all: --target "$site_packages" "$wheel"

cat > "$stage/DEBIAN/control" <<EOF
Package: opsai-cli
Version: $debian_version
Section: admin
Priority: optional
Architecture: $architecture
Depends: python3 (>= $python_minor), python3 (<< $python_major.$next_minor)
Maintainer: OpsAI maintainers
Description: Read-only system diagnostics with optional AI analysis
 OpsAI provides local DevOps diagnostics, log analysis, SSH monitoring,
 and Linux and Docker security auditing.
EOF

cat > "$stage/usr/bin/opsai" <<EOF
#!/bin/sh
set -eu
expected_python='$python_minor'
actual_python="\$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [ "\$actual_python" != "\$expected_python" ]; then
    printf 'OpsAI requires Python %s; found Python %s. Reinstall the matching package.\\n' \
        "\$expected_python" "\$actual_python" >&2
    exit 1
fi
export PYTHONPATH="/usr/lib/opsai/python$python_minor\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m opsai.cli "\$@"
EOF
chmod 755 "$stage/usr/bin/opsai"

package="$output_dir/opsai-cli_${version}_py${python_minor}_${architecture}.deb"
dpkg-deb --build --root-owner-group "$stage" "$package"
printf 'Built %s\n' "$package"
