PATH A STAGE16 HOTFIX

Fixes VPP crash:
  vlib_node_add_next_with_slot assertion `vlib_get_thread_index () == 0`

Root cause:
- stage16 called tlsctrl_vpn_stage16_feature_sync() from dp_attach/dp_configure
- those paths may run from a session worker thread during tunnel open
- vnet_feature_enable_disable() must run on the main thread

What changed:
- removed feature_sync calls from tlsctrl_vpn_dp_attach()
- removed feature_sync calls from tlsctrl_vpn_dp_configure()
- tlsctrl_vpn_stage16_feature_sync() now returns immediately if thread != 0
- stage16 feature remains enabled from plugin init, which is main-thread safe

Expected result:
- no crash on vpn-bind / tunnel-open
- stage16 reverse hook still works on interfaces present at plugin init

If later you need dynamic re-sync for interfaces created after plugin init,
add a process/main-thread event path instead of calling feature_enable_disable
directly from a worker callback.
