PATH-A Stage16 hotfix2

What was wrong
- stage13 synthetic autohook was still enabled by default, so outbound counters could grow without a real reverse lookup
- stage16 feature sync only ran during init, so reverse hook might never get enabled on the real ingress interface

What changed
- stage13 synthetic autohook is now debug-only and disabled by default
- added main-thread process node tlsctrl-vpn-stage16-sync that periodically enables stage16 feature on all interfaces

Expected result
- txlookup should start growing on real replies
- autohook should stay 0 unless explicitly enabled by CLI
