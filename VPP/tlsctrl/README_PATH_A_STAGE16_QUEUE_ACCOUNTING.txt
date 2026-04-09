STAGE16 queue accounting cleanup

What changed:
- queue depth is now owned only by dataplane enqueue/dequeue paths
- generic transport packet accounting no longer increments q
- frame tx/rx accounting no longer double-counts keepalive/ipv4 events
- dataplane CLI now shows qstat=enqueued/dequeued/dropped and qb=enqueued_bytes/dequeued_bytes

Expected result:
- q should reflect actual pending reverse frames, not cumulative traffic
- txf/rxf/ip4tx/ip4rx should stop inflating from duplicate accounting
- if replies are drained correctly, q should stay near 0 under steady ping
