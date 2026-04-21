#ifndef included_radius_pending_h
#define included_radius_pending_h

#include "radius.h"

radius_pending_req_t *radius_pending_add(radius_auth_req_t *req, u64 *txn_id);
radius_pending_req_t *radius_pending_get(u64 txn_id);
void radius_pending_remove(u64 txn_id);

#endif
