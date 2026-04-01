#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./hack/generate-binapi.sh /path/to/vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api
#
# The path above should contain *.api.json files produced by your VPP build
# and must include the plugin API for tlsctrl.

API_INPUT="${1:-}"
if [[ -z "${API_INPUT}" ]]; then
  echo "usage: $0 <vpp-api-dir>"
  echo "example: $0 ~/vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api"
  exit 1
fi

BINAPI_GEN="${BINAPI_GEN:-binapi-generator}"

"${BINAPI_GEN}" --input="${API_INPUT}" --output-dir=internal/vppbinapi

echo
echo "Done. Check that generated package exists:"
echo "  internal/vppbinapi/tlsctrl"
echo
echo "Then build agent with real GovPP backend:"
echo "  go build -tags govpp -o bin/tlsctrl-agent ./cmd/tlsctrl-agent"
