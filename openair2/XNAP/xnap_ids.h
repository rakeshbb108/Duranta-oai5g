/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* XnAP UE association table — private to the XnAP task (single-threaded, no locking).
 *
 * XnAP is the sole owner of Xn UE identifiers: the local NG-RAN node UE XnAP ID
 * (allocated here, for both roles), the remote one (learned from the peer), the
 * Xn-C peer association, and the role. RRC only ever sees rrc_ue_id, except for
 * the opaque xn_token (== local_xnap_id) handed to the target RRC with an incoming
 * HandoverRequest, before an rrc_ue_id exists; it is bound on HandoverRequestAck. */

#ifndef XNAP_IDS_H_
#define XNAP_IDS_H_

#include <stdbool.h>
#include <stdint.h>
#include "common/platform_types.h"
#include "openair2/COMMON/sctp_messages_types.h"
#include "xnap_ho_sm.h"

/* rrc_ue_id of a target entry whose HandoverRequest is still pending in RRC
 * (RRC UE IDs start at 1) */
#define XN_UE_RRC_ID_UNBOUND 0

typedef enum { XN_ROLE_SOURCE, XN_ROLE_TARGET } xn_ue_role_t;

typedef struct {
  uint32_t local_xnap_id;  /* allocated by this node (s-ID at source, t-ID at target) */
  uint32_t remote_xnap_id; /* learned from peer */
  bool remote_valid;
  uint32_t rrc_ue_id;      /* XN_UE_RRC_ID_UNBOUND while target HO Request pending */
  xn_ue_role_t role;
  sctp_assoc_t assoc_id;   /* Xn-C peer */
  /* Handover state machine (xnap_ho_sm.h); the field matching `role` is used */
  xnap_ho_src_state_t src_state;
  xnap_ho_tgt_state_t tgt_state;
  xnap_ho_src_timer_marks_t timer_marks; /* source only */
} xn_ue_assoc_t;

void xn_ue_init(void);
/* Single allocator for both roles; never returns 0, skips ids in use */
uint32_t xn_ue_alloc_local_id(void);
bool xn_ue_add(const xn_ue_assoc_t *a);
xn_ue_assoc_t *xn_ue_get_by_local(uint32_t local_xnap_id);
xn_ue_assoc_t *xn_ue_get_by_rrc(uint32_t rrc_ue_id);
/* Target entry matching the peer's (source) XnAP ID on the given association */
xn_ue_assoc_t *xn_ue_get_target_by_remote(sctp_assoc_t assoc_id, uint32_t remote_xnap_id);
bool xn_ue_bind_rrc(uint32_t local_xnap_id, uint32_t rrc_ue_id);
void xn_ue_remove(uint32_t local_xnap_id);
/* Remove every entry on assoc_id; on_ue (may be NULL) sees each entry just before removal */
void xn_ue_purge_assoc(sctp_assoc_t assoc_id, void (*on_ue)(const xn_ue_assoc_t *a, void *ctx), void *ctx);

/* Bounded roster of source-side UEs with a running TXnRELOCprep/TXnRELOCoverall
 * timer, scanned once per tick by xnap_check_ho_timers() (xnap_ho_timers.c).
 * Mirrors X2AP's fixed-size x2ap_id_manager.ids[X2AP_MAX_IDS] (openair2/X2AP/x2ap_ids.h). */
#define XNAP_MAX_HO_TIMERS 16
void xnap_ho_timer_track(uint32_t local_xnap_id);
void xnap_ho_timer_untrack(uint32_t local_xnap_id);
/* Copies up to max_ids tracked ids into out_ids; returns how many were copied. */
int xnap_ho_get_tracked_source_ids(uint32_t out_ids[], int max_ids);

#endif /* XNAP_IDS_H_ */
