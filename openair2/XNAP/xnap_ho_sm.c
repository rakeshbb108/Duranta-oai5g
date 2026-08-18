/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "xnap_ho_sm.h"
#include "common/utils/LOG/log.h"

/* ======================================================================== */
/* Source role                                                               */
/* ======================================================================== */

xnap_ho_src_result_t xnap_ho_src_transition(xnap_ho_src_state_t state, xnap_ho_src_event_t event)
{
  switch (state) {
    case XNAP_HO_SRC_SCTP_READY:
      /* Bringing up Xn Setup (TS 38.423 §8.4.1) is driven directly by the
       * caller (SCTP association coming up IS the trigger, there is no peer
       * message or timer to react to yet) — the caller issues
       * XNAP_HO_SRC_ACT_SEND_XN_SETUP_REQUEST and moves to
       * XNAP_HO_SRC_XN_SETUP_REQ_SENT itself; no event exists for it here. */
      break;

    case XNAP_HO_SRC_XN_SETUP_REQ_SENT:
      switch (event) {
        case XNAP_HO_SRC_EV_XN_SETUP_RESPONSE: /* TS 38.423 §8.4.1: Xn Setup succeeds */
          return (xnap_ho_src_result_t){XNAP_HO_SRC_XN_READY, XNAP_HO_SRC_ACT_NONE};
        case XNAP_HO_SRC_EV_XN_SETUP_FAILURE: /* TS 38.423 §8.4.1: Xn Setup rejected by peer */
          return (xnap_ho_src_result_t){XNAP_HO_SRC_SCTP_READY, XNAP_HO_SRC_ACT_RETRY_XN_SETUP};
        default:
          break;
      }
      break;

    case XNAP_HO_SRC_XN_READY:
      switch (event) {
        case XNAP_HO_SRC_EV_HO_TRIGGER: /* TS 38.423 §8.2.1.2: source starts Handover Preparation */
          return (xnap_ho_src_result_t){XNAP_HO_SRC_HO_REQ_SENT, XNAP_HO_SRC_ACT_SEND_HANDOVER_REQUEST};
        default:
          break;
      }
      break;

    case XNAP_HO_SRC_HO_REQ_SENT:
      switch (event) {
        case XNAP_HO_SRC_EV_HANDOVER_REQUEST_ACK:
          /* TS 38.423 §9.1.1.2 rx: preparation succeeded, source now has a
           * "Prepared Handover" (§8.2.1.2). TXnRELOCprep stops and
           * TXnRELOCoverall starts in the same instant (immediate handover:
           * the two never overlap). */
          return (xnap_ho_src_result_t){XNAP_HO_SRC_HO_PREPARED, XNAP_HO_SRC_ACT_SEND_SN_STATUS_TRANSFER};
        case XNAP_HO_SRC_EV_HANDOVER_PREP_FAILURE:
          /* TS 38.423 §9.1.1.3 rx: target admission failed. No Prepared
           * Handover was ever established, so there is nothing to cancel —
           * just stop TXnRELOCprep and go back to steady state. */
          return (xnap_ho_src_result_t){XNAP_HO_SRC_XN_READY, XNAP_HO_SRC_ACT_TERMINATE_PREPARATION};
        case XNAP_HO_SRC_EV_TIMER_RELOCPREP_EXPIRY:
          /* §8.2.1.2: TXnRELOCprep expired before an Ack/Failure arrived —
           * cancel the not-yet-completed preparation. HANDOVER CANCEL is a
           * Class 2 (no-response) procedure; the source does not wait for
           * anything back before returning to steady state. */
          return (xnap_ho_src_result_t){XNAP_HO_SRC_XN_READY, XNAP_HO_SRC_ACT_SEND_HANDOVER_CANCEL};
        default:
          break;
      }
      break;

    case XNAP_HO_SRC_HO_PREPARED:
      switch (event) {
        case XNAP_HO_SRC_EV_UE_CONTEXT_RELEASE:
          /* TS 38.423 §9.1.1.5 rx: the UE has left, handover is complete.
           * Stop TXnRELOCoverall. */
          return (xnap_ho_src_result_t){XNAP_HO_SRC_HO_COMPLETE, XNAP_HO_SRC_ACT_LOCAL_RELEASE};
        case XNAP_HO_SRC_EV_TIMER_RELOCOVERALL_EXPIRY:
          /* §8.2.1.2: TXnRELOCoverall expired — relocation has failed even
           * though preparation succeeded (e.g. UE never arrived and the
           * target never reached Path Switch). Cancel and clean up locally;
           * again no response is expected from HANDOVER CANCEL. */
          return (xnap_ho_src_result_t){XNAP_HO_SRC_XN_READY, XNAP_HO_SRC_ACT_CANCEL_AND_RELEASE};
        default:
          break;
      }
      break;

    case XNAP_HO_SRC_HO_COMPLETE:
      /* Terminal for this HO attempt. The caller resets/discards the per-UE
       * context; no further event is expected to reach this state. */
      break;
  }

  LOG_W(XNAP, "xnap_ho_src_transition: illegal event %d in state %d\n", event, state);
  return (xnap_ho_src_result_t){state, XNAP_HO_SRC_ACT_ILLEGAL};
}

/* ======================================================================== */
/* Target role                                                               */
/* ======================================================================== */

xnap_ho_tgt_result_t xnap_ho_tgt_transition(xnap_ho_tgt_state_t state, xnap_ho_tgt_event_t event)
{
  switch (state) {
    case XNAP_HO_TGT_SCTP_READY:
      switch (event) {
        case XNAP_HO_TGT_EV_XN_SETUP_REQUEST: /* TS 38.423 §8.4.1: peer initiates Xn Setup */
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_XN_SETUP_PROCESSING, XNAP_HO_TGT_ACT_RUN_XN_SETUP_VALIDATION};
        default:
          break;
      }
      break;

    case XNAP_HO_TGT_XN_SETUP_PROCESSING:
      switch (event) {
        case XNAP_HO_TGT_EV_XN_SETUP_ACCEPTED: /* §8.4.1 */
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_XN_READY, XNAP_HO_TGT_ACT_SEND_XN_SETUP_RESPONSE};
        case XNAP_HO_TGT_EV_XN_SETUP_REJECTED: /* §8.4.1 */
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_SCTP_READY, XNAP_HO_TGT_ACT_SEND_XN_SETUP_FAILURE};
        default:
          break;
      }
      break;

    case XNAP_HO_TGT_XN_READY:
      switch (event) {
        case XNAP_HO_TGT_EV_HANDOVER_REQUEST: /* TS 38.423 §9.1.1.1 rx: run admission control */
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_HO_REQ_PROCESSING, XNAP_HO_TGT_ACT_RUN_ADMISSION_CONTROL};
        default:
          break;
      }
      break;

    case XNAP_HO_TGT_HO_REQ_PROCESSING:
      switch (event) {
        case XNAP_HO_TGT_EV_ADMISSION_ACCEPTED: /* §9.1.1.2 */
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_HO_REQ_ACK_SENT, XNAP_HO_TGT_ACT_SEND_HANDOVER_REQUEST_ACK};
        case XNAP_HO_TGT_EV_ADMISSION_REJECTED:
          /* §9.1.1.3: no reserved context survives admission failure, so
           * there is nothing left for a HANDOVER CANCEL to release. */
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_XN_READY, XNAP_HO_TGT_ACT_SEND_HANDOVER_PREP_FAILURE};
        case XNAP_HO_TGT_EV_HANDOVER_CANCEL:
          /* §9.1.1.6: source gave up (its TXnRELOCprep expired) while
           * admission control was still running here. Release whatever was
           * reserved so far; Class 2 procedure, no reply. */
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_XN_READY, XNAP_HO_TGT_ACT_RELEASE_RESERVED_CONTEXT};
        default:
          break;
      }
      break;

    case XNAP_HO_TGT_HO_REQ_ACK_SENT:
      switch (event) {
        case XNAP_HO_TGT_EV_RRC_RECONFIG_COMPLETE:
          /* Air-interface event, NOT an Xn PDU: the UE has physically
           * arrived. Trigger the NG Path Switch procedure toward the AMF
           * (TS 38.413) — outside XnAP, no XnAP timer applies to it. */
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_UE_ARRIVED_PATH_SWITCHING, XNAP_HO_TGT_ACT_SEND_PATH_SWITCH_REQUEST};
        case XNAP_HO_TGT_EV_HANDOVER_CANCEL:
          /* §9.1.1.6: source's guard timer expired before the UE arrived —
           * the classic stale-target-context case this module relies on the
           * source to resolve (see file header). Release the reservation. */
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_XN_READY, XNAP_HO_TGT_ACT_RELEASE_RESERVED_CONTEXT};
        default:
          break;
      }
      break;

    case XNAP_HO_TGT_UE_ARRIVED_PATH_SWITCHING:
      switch (event) {
        case XNAP_HO_TGT_EV_PATH_SWITCH_SUCCESS:
          /* NG Path Switch Ack rx: UPF path now points at the target.
           * TS 38.423 §9.1.1.5: release the source's UE context over Xn. */
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_UE_CTXT_REL_SENT, XNAP_HO_TGT_ACT_SEND_UE_CONTEXT_RELEASE};
        case XNAP_HO_TGT_EV_PATH_SWITCH_FAILURE:
          return (xnap_ho_tgt_result_t){XNAP_HO_TGT_XN_READY, XNAP_HO_TGT_ACT_LOCAL_RELEASE_PATH_SWITCH_FAILURE};
        /* A HANDOVER CANCEL rx here is deliberately NOT handled: the UE has
         * already left the source's cell over the air, so a source-side
         * cancel racing this state is stale and ignored (falls through to
         * the illegal-transition guard below rather than being acted on). */
        default:
          break;
      }
      break;

    case XNAP_HO_TGT_UE_CTXT_REL_SENT:
      /* Terminal for this HO attempt. The caller resets/discards the per-UE
       * context; no further event is expected to reach this state. */
      break;
  }

  LOG_W(XNAP, "xnap_ho_tgt_transition: illegal event %d in state %d\n", event, state);
  return (xnap_ho_tgt_result_t){state, XNAP_HO_TGT_ACT_ILLEGAL};
}

/* ======================================================================== */
/* Timer scaffolding (source-only)                                          */
/* ======================================================================== */

void xnap_ho_src_timers_init(xnap_ho_src_timers_t *t, int t_xn_reloc_prep, int t_xn_reloc_overall)
{
  t->tti = 0;
  t->t_xn_reloc_prep = t_xn_reloc_prep;
  t->t_xn_reloc_overall = t_xn_reloc_overall;
}

void xnap_ho_src_set_relocprep_start(xnap_ho_src_timer_marks_t *m, uint64_t now)
{
  m->t_xn_reloc_prep_start = now;
}

void xnap_ho_src_set_relocoverall_start(xnap_ho_src_timer_marks_t *m, uint64_t now)
{
  m->t_xn_reloc_overall_start = now;
}

bool xnap_ho_src_timer_check(xnap_ho_src_state_t state,
                              const xnap_ho_src_timer_marks_t *marks,
                              const xnap_ho_src_timers_t *timers,
                              xnap_ho_src_event_t *expired)
{
  /* Which mark to check is implied by `state`, exactly as X2AP keys off
   * x2id_state_t (x2ap_timers.c) rather than a separate "which timer is
   * active" field — TXnRELOCprep/TXnRELOCoverall never run concurrently. */
  if (state == XNAP_HO_SRC_HO_REQ_SENT
      && timers->tti > marks->t_xn_reloc_prep_start + (uint64_t)timers->t_xn_reloc_prep) {
    *expired = XNAP_HO_SRC_EV_TIMER_RELOCPREP_EXPIRY;
    return true;
  }

  if (state == XNAP_HO_SRC_HO_PREPARED
      && timers->tti > marks->t_xn_reloc_overall_start + (uint64_t)timers->t_xn_reloc_overall) {
    *expired = XNAP_HO_SRC_EV_TIMER_RELOCOVERALL_EXPIRY;
    return true;
  }

  return false;
}
