fixed13:
- manual disconnect now marks dataplane stopping before any disconnect heartbeat
- activeBase/activeClient are detached before dataplane shutdown wait
- disconnect heartbeat uses captured http client instead of global activeClient
- this prevents postFrame/pollFrame from hitting empty URL during normal disconnect
