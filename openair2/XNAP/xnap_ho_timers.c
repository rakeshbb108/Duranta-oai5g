/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "xnap_ho_timers.h"
#include "xnap_ho_sm.h"
#include "xnap_ids.h"
#include "common/utils/LOG/log.h"
#include "common/utils/ocp_itti/intertask_interface.h"
#include "openair2/COMMON/xnap_messages_types.h"

/* Advanced by XNAP_HO_TIMER_TICK_MS on every tick (xnap_gNB.c); tti is in
 * milliseconds, so t_xn_reloc_prep/t_xn_reloc_overall (also milliseconds)
 * compare directly — no unit conversion needed. */
static xnap_ho_src_timers_t g_xnap_ho_timers;

void xnap_ho_timers_init(uint32_t t_xn_reloc_prep_ms, uint32_t t_xn_reloc_overall_ms)
{
  xnap_ho_src_timers_init(&g_xnap_ho_timers, (int)t_xn_reloc_prep_ms, (int)t_xn_reloc_overall_ms);
  LOG_I(XNAP, "Xn HO guard timers: TXnRELOCprep=%ums TXnRELOCoverall=%ums\n",
        t_xn_reloc_prep_ms, t_xn_reloc_overall_ms);
}

/* Re-injects HandoverCancel through the normal ITTI dispatch (XNAP_HANDOVER_CANCEL
 * case in xnap_gNB_task()) rather than calling the RRC-triggered send function
 * directly — keeps this file decoupled from xnap_gNB.c's internals. */
static void send_handover_cancel(instance_t instance, uint32_t xnap_ue_id, uint8_t cause_value)
{
  MessageDef *msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_HANDOVER_CANCEL);
  XNAP_HANDOVER_CANCEL(msg) = (xnap_handover_cancel_t){
    .s_ng_node_ue_xnap_id = xnap_ue_id,
    .cause = {.type = XNAP_CAUSE_RADIO_NETWORK, .value = cause_value},
  };
  itti_send_msg_to_task(TASK_XNAP, instance, msg);
}

/* Tells RRC to release its side locally — no XnAP message carries this
 * information (see xnap_ho_sm.h header note on the two source timers). */
static void notify_rrc_timeout(instance_t instance, uint32_t rrc_ue_id, bool overall)
{
  MessagesIds msg_id = overall ? XNAP_HO_RELOCOVERALL_TIMEOUT : XNAP_HO_RELOCPREP_TIMEOUT;
  MessageDef *msg = itti_alloc_new_message(TASK_XNAP, instance, msg_id);
  if (overall)
    XNAP_HO_RELOCOVERALL_TIMEOUT(msg).rrc_ue_id = rrc_ue_id;
  else
    XNAP_HO_RELOCPREP_TIMEOUT(msg).rrc_ue_id = rrc_ue_id;
  itti_send_msg_to_task(TASK_RRC_GNB, instance, msg);
}

uint64_t xnap_ho_timers_now(void)
{
  return g_xnap_ho_timers.tti;
}

void xnap_check_ho_timers(instance_t instance)
{
  g_xnap_ho_timers.tti += XNAP_HO_TIMER_TICK_MS;

  uint32_t ids[XNAP_MAX_HO_TIMERS];
  int n = xnap_ho_get_tracked_source_ids(ids, XNAP_MAX_HO_TIMERS);

  for (int i = 0; i < n; i++) {
    uint32_t xnap_ue_id = ids[i];
    if (!xnap_exists_ue_data(xnap_ue_id)) {
      /* UE removed (e.g. UE Context Release already processed) without
       * going through xnap_ho_timer_untrack — stale slot, drop it. */
      xnap_ho_timer_untrack(xnap_ue_id);
      continue;
    }

    xnap_ue_data_t data = xnap_get_ue_data(xnap_ue_id);
    xnap_ho_src_event_t expired_event;
    if (!xnap_ho_src_timer_check(data.sm_state, &data.timer_marks, &g_xnap_ho_timers, &expired_event))
      continue;

    bool overall = expired_event == XNAP_HO_SRC_EV_TIMER_RELOCOVERALL_EXPIRY;
    xnap_ho_src_result_t r = xnap_ho_src_transition(data.sm_state, expired_event);

    LOG_W(XNAP, "[gNB %ld] xnap_ue_id %u (rrc_ue_id %u): %s expired — sending HandoverCancel\n",
          instance, xnap_ue_id, data.rrc_ue_id, overall ? "TXnRELOCoverall" : "TXnRELOCprep");

    /* Both expiry actions leave {HO_REQ_SENT, HO_PREPARED} for good (see
     * xnap_ho_sm.c) so the roster slot is freed here, not re-armed. */
    xnap_set_ue_sm_state(xnap_ue_id, r.next_state);
    xnap_ho_timer_untrack(xnap_ue_id);

    /* Do NOT remove xnap_ue_data here: send_handover_cancel() only enqueues
     * XNAP_HANDOVER_CANCEL, it doesn't send it - the actual encode/send (and
     * matching xnap_remove_ue_data()) happens later, when xnap_gNB_task()
     * dequeues that message and runs xnap_gNB_generate_handover_cancel().
     * Removing the entry here would make that lookup fail and silently drop
     * the Cancel instead of sending it (this was a real, observed bug). */
    send_handover_cancel(instance,
                          xnap_ue_id,
                          overall ? XNAP_CAUSE_RADIO_NETWORK_LAYER_TXN_RELOCOVERALL_EXPIRY
                                  : XNAP_CAUSE_RADIO_NETWORK_LAYER_TXN_RELOCPREP_EXPIRY);
    notify_rrc_timeout(instance, data.rrc_ue_id, overall);
  }
}
