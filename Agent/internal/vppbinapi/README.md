This directory is intentionally empty in the default archive.

For the real GovPP backend you must generate Go bindings from your VPP tree
that already contains `src/plugins/tlsctrl/tlsctrl.api`.

Expected package path after generation:
- `internal/vppbinapi/tlsctrl`

The `govpp` build-tag code imports:
- `github.com/srmkv/tlsctrl-agent/internal/vppbinapi/tlsctrl`
