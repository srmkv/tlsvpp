# tlsctrl-agent v20 (GovPP-only VPN profile sync)

This version removes the **runtime dependency on `vppctl`** for VPN runtime objects.

## What changed

- `SyncVPNProfiles()` now uses **GovPP / binary API** instead of shelling out to:
  - `tlsctrl vpn pool set ...`
  - `tlsctrl vpn profile set ...`

## Architecture

- `client -> vpp plugin`
- `go agent -> vpp plugin` via **GovPP / binary API only**
- `web -> go agent`

## IMPORTANT

This source tree includes the full `tlsctrl_vpn` message layout based on the plugin API in `api/tlsctrl_vpn.api`.

After you apply the plugin patch and rebuild VPP, regenerate the exact Go bindings with:

```bash
./hack/generate-binapi.sh /path/to/vpp/share/vpp/api
```

and make sure the generated custom package exists at:

- `internal/vppbinapi/tlsctrlvpn`

The source tree no longer shells out to `vppctl` and the VPN runtime calls go through the custom GovPP package.
For production runtime use, regenerate from the actual plugin API to get exact message CRCs from the plugin build.

## Build after regeneration

```bash
go mod tidy
go build -tags govpp -o bin/tlsctrl-agent ./cmd/tlsctrl-agent
```
