#!/bin/sh
# Install a pre-built oauth2c release. Go is not required.
#
#   curl -fsSL https://raw.githubusercontent.com/sukujgrg/oauth2c/master/scripts/install.sh | sh
#
# Optional:
#   OAUTH2C_VERSION=v2.1.0   pin a release (default: latest)
#   OAUTH2C_BINDIR=~/.local/bin   install directory (default: ~/.local/bin)
set -eu

REPO="sukujgrg/oauth2c"
BINDIR="${OAUTH2C_BINDIR:-${HOME}/.local/bin}"
VERSION="${OAUTH2C_VERSION:-}"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "oauth2c install: missing $1" >&2
		exit 1
	fi
}

need curl
need tar
need uname

os=$(uname -s)
arch=$(uname -m)
case "$os" in
Darwin) os_name=Darwin ;;
Linux) os_name=Linux ;;
*)
	echo "oauth2c install: unsupported OS '$os' (use scripts/install.ps1 on Windows)" >&2
	exit 1
	;;
esac
case "$arch" in
x86_64 | amd64) arch_name=x86_64 ;;
arm64 | aarch64) arch_name=arm64 ;;
armv7l | armv6l | arm) arch_name=arm ;;
*)
	echo "oauth2c install: unsupported architecture '$arch'" >&2
	exit 1
	;;
esac

if [ -z "$VERSION" ]; then
	VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
		sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
fi
if [ -z "$VERSION" ]; then
	echo "oauth2c install: could not determine the latest release" >&2
	exit 1
fi
version_num=${VERSION#v}

asset="oauth2c_${version_num}_${os_name}_${arch_name}.tar.gz"
base="https://github.com/${REPO}/releases/download/${VERSION}"
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

echo "Installing oauth2c ${VERSION} (${os_name}/${arch_name}) to ${BINDIR}"
curl -fsSL -o "${tmpdir}/${asset}" "${base}/${asset}"
curl -fsSL -o "${tmpdir}/checksums.txt" "${base}/checksums.txt"

if command -v sha256sum >/dev/null 2>&1; then
	(cd "$tmpdir" && grep " ${asset}\$" checksums.txt | sha256sum -c -)
elif command -v shasum >/dev/null 2>&1; then
	(cd "$tmpdir" && grep " ${asset}\$" checksums.txt | shasum -a 256 -c -)
else
	echo "oauth2c install: no sha256sum/shasum; skipping checksum" >&2
fi

tar -xzf "${tmpdir}/${asset}" -C "$tmpdir"
src=$(find "$tmpdir" -type f -name oauth2c | head -n 1)
if [ -z "$src" ]; then
	echo "oauth2c install: archive did not contain oauth2c" >&2
	exit 1
fi

mkdir -p "$BINDIR"
cp "$src" "${BINDIR}/oauth2c"
chmod +x "${BINDIR}/oauth2c"

if ! command -v oauth2c >/dev/null 2>&1; then
	echo "Installed ${BINDIR}/oauth2c"
	echo "Add ${BINDIR} to PATH, for example:"
	echo "  export PATH=\"${BINDIR}:\$PATH\""
else
	oauth2c version
fi
