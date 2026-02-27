#!/bin/bash
# install-deps.sh — Install podtrace build dependencies for the current distro.
#
# Supported:
#   Debian / Ubuntu
#   RHEL / CentOS / AlmaLinux / Rocky Linux (8/9)
#   Fedora
#   Alpine Linux
#   Talos Linux (instructions only — read-only rootfs, no package manager)
#
# Usage:
#   sudo ./scripts/install-deps.sh
#
set -euo pipefail

KERNEL_RELEASE=$(uname -r)

detect_distro() {
	if [[ -f /etc/os-release ]]; then
		# shellcheck source=/dev/null
		source /etc/os-release
		echo "${ID:-unknown}"
	elif command -v lsb_release &>/dev/null; then
		lsb_release -si | tr '[:upper:]' '[:lower:]'
	else
		echo "unknown"
	fi
}

check_root() {
	if [[ ${EUID} -ne 0 ]]; then
		echo "Error: run this script as root (sudo ./scripts/install-deps.sh)" >&2
		exit 1
	fi
}

install_debian_ubuntu() {
	echo "Detected Debian/Ubuntu — installing via apt-get..."
	apt-get update -q

	# linux-tools provides bpftool; try the versioned package first, then generic.
	TOOLS_PKG="linux-tools-${KERNEL_RELEASE}"
	if ! apt-cache show "${TOOLS_PKG}" &>/dev/null; then
		TOOLS_PKG="linux-tools-generic"
	fi

	HEADERS_PKG="linux-headers-${KERNEL_RELEASE}"
	if ! apt-cache show "${HEADERS_PKG}" &>/dev/null; then
		HEADERS_PKG="linux-headers-generic"
	fi

	apt-get install -y \
		clang \
		llvm \
		libbpf-dev \
		"${HEADERS_PKG}" \
		"${TOOLS_PKG}" \
		libcap2-bin

	install_go_if_needed
}

install_rhel_centos() {
	echo "Detected RHEL/CentOS/AlmaLinux/Rocky — installing via dnf..."

	# Enable EPEL for bpftool if not already enabled.
	if ! rpm -q epel-release &>/dev/null; then
		if command -v dnf &>/dev/null; then
			dnf install -y epel-release || true
		fi
	fi

	PKG_MGR="dnf"
	if ! command -v dnf &>/dev/null; then
		PKG_MGR="yum"
	fi

	"${PKG_MGR}" install -y \
		clang \
		llvm \
		libbpf-devel \
		kernel-devel \
		bpftool \
		libcap

	install_go_if_needed
}

install_fedora() {
	echo "Detected Fedora — installing via dnf..."
	dnf install -y \
		clang \
		llvm \
		libbpf-devel \
		kernel-devel \
		bpftool \
		libcap

	install_go_if_needed
}

install_alpine() {
	echo "Detected Alpine Linux — installing via apk..."
	# Alpine uses musl libc; BPF programs still compile fine against the glibc
	# headers in linux-headers. Note: Alpine kernel ships without BTF by default
	# on some versions — use linux-lts or linux-edge for BTF support.
	apk add --no-cache \
		clang \
		llvm \
		libbpf-dev \
		linux-headers \
		bpftool \
		libcap

	install_go_if_needed
}

install_go_if_needed() {
	local required="1.24"
	local go_bin=""

	for candidate in /usr/local/go/bin/go go; do
		if command -v "${candidate}" &>/dev/null; then
			go_bin="${candidate}"
			break
		fi
	done

	if [[ -n "${go_bin}" ]]; then
		local current
		current=$("${go_bin}" version 2>/dev/null | awk '{print $3}' | tr -d 'go')
		local major minor
		major=$(echo "${current}" | cut -d. -f1)
		minor=$(echo "${current}" | cut -d. -f2)
		if [[ "${major}" -ge 1 && "${minor}" -ge 24 ]]; then
			echo "Go ${current} already installed and satisfies requirement (>=${required})."
			return
		fi
		echo "Installed Go ${current} is below ${required}."
	else
		echo "Go not found."
	fi

	echo "Installing Go ${required}..."
	local arch
	arch=$(uname -m)
	case "${arch}" in
		x86_64)  arch_tag="amd64" ;;
		aarch64) arch_tag="arm64" ;;
		ppc64le) arch_tag="ppc64le" ;;
		s390x)   arch_tag="s390x" ;;
		*)       echo "Warning: unsupported arch ${arch}, install Go manually from https://go.dev/dl/"; return ;;
	esac

	local tarball="go${required}.linux-${arch_tag}.tar.gz"
	local url="https://go.dev/dl/${tarball}"

	echo "Downloading ${url}..."
	if command -v curl &>/dev/null; then
		curl -fsSL "${url}" -o "/tmp/${tarball}"
	elif command -v wget &>/dev/null; then
		wget -q "${url}" -O "/tmp/${tarball}"
	else
		echo "Error: neither curl nor wget found. Install Go manually from https://go.dev/dl/"
		return
	fi

	rm -rf /usr/local/go
	tar -C /usr/local -xzf "/tmp/${tarball}"
	rm "/tmp/${tarball}"

	echo "Go ${required} installed to /usr/local/go."
	echo "Add to PATH: export PATH=\$PATH:/usr/local/go/bin"
}

talos_instructions() {
	cat <<'EOF'
Talos Linux detected — or running in a read-only OS environment.

Talos has a read-only rootfs and no package manager. Build podtrace on a
separate Linux machine and copy the binary to the node:

  # On a build machine (Debian/Ubuntu/Fedora):
  sudo ./scripts/install-deps.sh
  make build

  # Cross-compile for the Talos node arch (usually amd64 or arm64):
  GOARCH=amd64 make build   # or GOARCH=arm64

  # Copy to the Talos node via SCP or embed in a DaemonSet image.
  # Talos ships BTF-enabled kernels (v1.3+), so PODTRACE_VMLINUX_FROM_BTF
  # will be set automatically when bpftool is available.

  # DaemonSet deployment: see docs/cloud/talos.md

EOF
	exit 0
}

main() {
	# Detect Talos: /etc/os-release ID=talos or immutable rootfs marker.
	if grep -qi "talos" /etc/os-release 2>/dev/null || [[ -f /etc/talos/config.yaml ]]; then
		talos_instructions
	fi

	check_root

	local distro
	distro=$(detect_distro)

	case "${distro}" in
		debian|ubuntu|linuxmint|pop)
			install_debian_ubuntu
			;;
		rhel|centos|almalinux|rocky|ol)
			install_rhel_centos
			;;
		fedora)
			install_fedora
			;;
		alpine)
			install_alpine
			;;
		*)
			echo "Unsupported distro: '${distro}'"
			echo ""
			echo "Manual install — required packages:"
			echo "  clang, llvm, libbpf-dev (or libbpf-devel), linux-headers, bpftool, Go 1.24+"
			echo "  See https://github.com/podtrace/podtrace for details."
			exit 1
			;;
	esac

	echo ""
	echo "Dependencies installed. You can now build podtrace:"
	echo "  ./scripts/build-and-setup.sh"
}

main "$@"
