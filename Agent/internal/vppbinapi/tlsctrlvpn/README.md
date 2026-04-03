This package mirrors the custom plugin API from `api/tlsctrl_vpn.api`.

It now contains the full message set used by the plugin runtime:
- pool set / dump
- profile set / dump
- connect-config get
- tunnel open / close / dump

Important:
- the message layout matches the plugin API source in this repository
- the exact VPP message CRC values still must match the plugin build
- after rebuilding the plugin, regenerate this package from the produced `tlsctrl_vpn.api.json`
  to get final CRC values for production runtime use
