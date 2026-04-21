#ifndef included_radius_transport_h
#define included_radius_transport_h

#include "radius.h"

int radius_transport_send_access_request(radius_pending_req_t *pr,
                                         radius_server_t *provider,
                                         const u8 *password,
                                         const u8 *nas_id);

#endif
