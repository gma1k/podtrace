#!/bin/bash
# Script to set capabilities on podtrace binary to run without sudo

set -e

BINARY="./bin/podtrace"

check_binary_exists() {
    if [[ ! -f "${BINARY}" ]]; then
        echo "Error: ${BINARY} not found. Build it first with 'make build'"
        exit 1
    fi
}

set_capabilities() {
    echo "Setting capabilities on ${BINARY}..."
    echo "This allows podtrace to run without sudo (for eBPF operations)"

    sudo setcap cap_bpf,cap_sys_admin,cap_sys_resource+ep "${BINARY}"
}

print_success_message() {
    echo ""
    echo "✓ Capabilities set successfully!"
    echo ""
    echo "You can now run podtrace without sudo:"
    echo "  ./bin/podtrace -n <namespace> <pod-name>"
    echo ""
    echo "Note: You may still need sudo for some operations, but eBPF should work."
    echo ""
    echo "To remove capabilities:"
    echo "  sudo setcap -r ${BINARY}"
}

main() {
    check_binary_exists
    set_capabilities
    print_success_message
}

main "$@"
