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


echo
echo "IMPORTANT for VPN runtime API:"
echo "  verify that custom package exists:"
echo "    internal/vppbinapi/tlsctrlvpn"
echo
echo "If the generator uses the plugin API file name directly, you may need to"
echo "copy or link the generated package to:"
echo "  internal/vppbinapi/tlsctrlvpn"
echo
echo "The source API file for this custom package is stored at:"
echo "  api/tlsctrl_vpn.api"


# Replace generator-produced tlsctrlvpn RPC helper with GovPP-compatible implementation.
if [[ -f internal/vppbinapi/tlsctrlvpn/tlsctrl_vpn_rpc.ba.go && -f hack/tlsctrl_vpn_rpc.compat.go ]]; then
  cp hack/tlsctrl_vpn_rpc.compat.go internal/vppbinapi/tlsctrlvpn/tlsctrl_vpn_rpc.ba.go
  echo "patched internal/vppbinapi/tlsctrlvpn/tlsctrl_vpn_rpc.ba.go"
fi
