#include "radius_pending.h"
#include "radius_codec.h"

radius_pending_req_t *
radius_pending_add(radius_auth_req_t *req, u64 *txn_id)
{
  radius_main_t *rm = &radius_main;
  radius_pending_req_t *pr;

  pool_get_zero(rm->pending, pr);
  pr->txn_id = ++rm->next_txn_id;
  pr->provider_index = req->provider_index;
  pr->consumer_index = req->consumer_index;
  pr->opaque_cookie = req->opaque_cookie;
  pr->created_at = vlib_time_now(rm->vlib_main);
  pr->deadline_at = pr->created_at + 5.0;
  pr->identifier = (u8)(pr->txn_id & 0xff);
  radius_random_authenticator(pr->request_authenticator);
  pr->username = vec_dup(req->username);
  pr->state = vec_dup(req->state);

  if (!rm->pending_by_txn)
    rm->pending_by_txn = hash_create(0, sizeof(uword));
  hash_set(rm->pending_by_txn, pr->txn_id, pr - rm->pending);

  if (txn_id)
    *txn_id = pr->txn_id;
  return pr;
}

radius_pending_req_t *
radius_pending_get(u64 txn_id)
{
  radius_main_t *rm = &radius_main;
  uword *p;
  p = hash_get(rm->pending_by_txn, txn_id);
  if (!p)
    return 0;
  return pool_elt_at_index(rm->pending, p[0]);
}

void
radius_pending_remove(u64 txn_id)
{
  radius_main_t *rm = &radius_main;
  radius_pending_req_t *pr;
  uword *p;

  p = hash_get(rm->pending_by_txn, txn_id);
  if (!p)
    return;

  pr = pool_elt_at_index(rm->pending, p[0]);
  vec_free(pr->username);
  vec_free(pr->state);
  pool_put(rm->pending, pr);
  hash_unset(rm->pending_by_txn, txn_id);
}
