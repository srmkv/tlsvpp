Stage30: automatic shard placement in agent

What this adds:
- shard registry persisted in agent-data/shards.json
- sticky automatic user->shard placement in agent-data/shard_placements.json
- bundle issue/reissue uses shard-specific client_public_url/server_name
- no per-user shard selection in normal UI
- admin API for shard registry only:
  GET/POST /api/admin/shards
  POST /api/admin/shards/delete
  GET /api/admin/shards/placement?username=<u>

Policy:
- if a user already has a healthy enabled shard assignment, reuse it
- otherwise choose the enabled shard with the lowest assigned_users/weight score
- if no shard registry exists, an implicit local shard is created from current TLS settings
