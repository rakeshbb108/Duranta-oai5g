/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* XnAP UE ID management — maps locally-assigned XnAP UE IDs to RRC UE IDs.
 *
 * Source gNB: allocates s_ng_node_ue_xnap_id when sending HandoverRequest;
 *   stores {rrc_ue_id, target_assoc_id} so ACK/Failure can be routed back.
 * Target gNB: allocates t_ng_node_ue_xnap_id when sending HandoverRequestAck;
 *   stores {rrc_ue_id, source_assoc_id} so subsequent messages can be routed. */

#ifndef XNAP_IDS_H_
#define XNAP_IDS_H_

#include <stdbool.h>
#include <stdint.h>
#include "common/platform_types.h"
#include "openair2/COMMON/sctp_messages_types.h"
#include "xnap_ho_sm.h"

/* Source-side entry: keyed on s_ng_node_ue_xnap_id */
typedef struct {
  uint32_t     rrc_ue_id;            /* RRC UE ID at source gNB */
  sctp_assoc_t target_assoc_id;      /* SCTP association to the target gNB */
  uint32_t     t_ng_node_ue_xnap_id; /* target XnAP UE ID; -1 until HandoverRequestAck arrives */
  /* Handover Preparation state machine + TXnRELOCprep/TXnRELOCoverall marks
   * (xnap_ho_sm.h). Owned here, not in RRC, so XNAP alone decides legality of
   * incoming/outgoing Xn HO messages. */
  xnap_ho_src_state_t       sm_state;
  xnap_ho_src_timer_marks_t timer_marks;
} xnap_ue_data_t;

/* Target-side entry: keyed on t_ng_node_ue_xnap_id. Only created once the
 * HandoverRequestAcknowledge is sent (no early allocation of t_ng_node_ue_xnap_id),
 * so sm_state tracking here starts at XNAP_HO_TGT_HO_REQ_ACK_SENT — admission
 * control (pre-Ack) stays untracked, as today. */
typedef struct {
  uint32_t     rrc_ue_id;            /* RRC UE ID at target gNB */
  sctp_assoc_t source_assoc_id;      /* SCTP association back to the source gNB */
  uint32_t     s_ng_node_ue_xnap_id; /* source XnAP UE ID from the HandoverRequest */
  xnap_ho_tgt_state_t sm_state;
} xnap_target_ue_data_t;

/* Call once when the XNAP task starts */
void xnap_init_ue_data(void);

/* Source-side table: keyed on s_ng_node_ue_xnap_id */
uint32_t       xnap_alloc_ue_id(void);
bool           xnap_add_ue_data(uint32_t xnap_ue_id, const xnap_ue_data_t *data);
bool           xnap_exists_ue_data(uint32_t xnap_ue_id);
xnap_ue_data_t xnap_get_ue_data(uint32_t xnap_ue_id);
bool           xnap_remove_ue_data(uint32_t xnap_ue_id);
bool           xnap_set_ue_target_id(uint32_t xnap_ue_id, uint32_t t_xnap_ue_id);
bool           xnap_set_ue_sm_state(uint32_t xnap_ue_id, xnap_ho_src_state_t state);
bool           xnap_set_ue_timer_mark_relocprep(uint32_t xnap_ue_id, uint64_t now);
bool           xnap_set_ue_timer_mark_relocoverall(uint32_t xnap_ue_id, uint64_t now);

/* Target-side table: keyed on t_ng_node_ue_xnap_id */
uint32_t              xnap_alloc_target_ue_id(void);
bool                  xnap_add_target_ue_data(uint32_t t_xnap_ue_id, const xnap_target_ue_data_t *data);
bool                  xnap_exists_target_ue_data(uint32_t t_xnap_ue_id);
xnap_target_ue_data_t xnap_get_target_ue_data(uint32_t t_xnap_ue_id);
bool                  xnap_remove_target_ue_data(uint32_t t_xnap_ue_id);
xnap_target_ue_data_t *xnap_find_target_ue_by_source_id(uint32_t s_xnap_ue_id, uint32_t *t_xnap_ue_id);
bool                  xnap_set_target_ue_sm_state(uint32_t t_xnap_ue_id, xnap_ho_tgt_state_t state);

/* Bounded roster of source-side UEs with a running TXnRELOCprep/TXnRELOCoverall
 * timer, scanned once per tick by xnap_check_ho_timers() (xnap_ho_timers.c).
 * Mirrors X2AP's fixed-size x2ap_id_manager.ids[X2AP_MAX_IDS] (openair2/X2AP/x2ap_ids.h) —
 * needed because xnap_ue_mapping is a plain hashtable with no iteration API. */
#define XNAP_MAX_HO_TIMERS 16
void     xnap_ho_timer_track(uint32_t xnap_ue_id);
void     xnap_ho_timer_untrack(uint32_t xnap_ue_id);
/* Copies up to max_ids tracked ids into out_ids; returns how many were copied. */
int      xnap_ho_get_tracked_source_ids(uint32_t out_ids[], int max_ids);

#endif /* XNAP_IDS_H_ */
