#include "radius.h"
#include "radius_codec.h"
#include "radius_pending.h"

#include <vlib/vlib.h>
#include <vnet/udp/udp.h>

typedef enum {
  RADIUS_REPLY_NEXT_DROP,
  RADIUS_REPLY_N_NEXT,
} radius_reply_next_t;

static uword
radius_reply_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node,
                     vlib_frame_t *frame)
{
  radius_main_t *rm = &radius_main;
  u32 n_left_from, *from;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u8 *pkt;
      u32 len;
      radius_decoded_resp_t decoded = {0};
      radius_pending_req_t *pr = 0;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer(vm, bi0);
      pkt = vlib_buffer_get_current(b0);
      len = vlib_buffer_length_in_chain(vm, b0);

      if (radius_decode_response(pkt, len, &decoded) < 0)
        {
          rm->stats.errors++;
          goto done0;
        }

      pool_foreach(pr, rm->pending) {
        if (pr->identifier == decoded.identifier)
          break;
        pr = 0;
      }

      if (!pr)
        {
          rm->stats.errors++;
          goto done0;
        }

      {
        radius_auth_res_t res = {
          .opaque_cookie = pr->opaque_cookie,
          .txn_id = pr->txn_id,
          .reply_message = decoded.reply_message,
          .filter_id = decoded.filter_id,
          .state = decoded.state,
          .session_timeout = decoded.session_timeout,
          .idle_timeout = decoded.idle_timeout,
        };

        switch (decoded.code)
          {
          case RADIUS_CODE_ACCESS_ACCEPT:
            rm->stats.accepts++;
            res.result_code = RADIUS_RESULT_ACCEPT;
            break;
          case RADIUS_CODE_ACCESS_REJECT:
            rm->stats.rejects++;
            res.result_code = RADIUS_RESULT_REJECT;
            break;
          case RADIUS_CODE_ACCESS_CHALLENGE:
            rm->stats.challenges++;
            res.result_code = RADIUS_RESULT_CHALLENGE;
            break;
          default:
            rm->stats.errors++;
            res.result_code = RADIUS_RESULT_ERROR;
            break;
          }

        radius_record_event(pr, &res);
        radius_dispatch_result(&res);
        radius_pending_remove(pr->txn_id);
      }

    done0:
      radius_decoded_resp_free(&decoded);
      vlib_buffer_free(vm, &bi0, 1);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE(radius_reply_node) = {
  .function = radius_reply_node_fn,
  .name = "radius-reply-input",
  .vector_size = sizeof(u32),
  .format_trace = format_vlib_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = RADIUS_REPLY_N_NEXT,
  .next_nodes = {
    [RADIUS_REPLY_NEXT_DROP] = "error-drop",
  },
};
