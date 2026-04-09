Stage17 hardening

What changed:
- dataplane runtime counters are reset on new attach/reconnect
- lifecycle counters added: generation/open/close/reset
- detach now flushes pending frames as queue drops with byte accounting
- queue bytes now expose drop bytes too: qb=enq/deq/drop
- transport view gets matching lifecycle counters

Expected effect:
- reconnect starts from clean runtime telemetry
- disconnect with pending frames does not hide drops
- queue/accounting stays honest across reopen/close cycles
