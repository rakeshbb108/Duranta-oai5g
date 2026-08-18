/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* Xn-based inter-gNB handover state machine (TS 38.423), immediate handover only.
 *
 * Framework-agnostic core: this module owns only state + the two source-side
 * guard timers (TXnRELOCprep, TXnRELOCoverall). It does not touch ITTI, XNAP
 * ASN.1 encode/decode, or RRC internals — callers drive it by feeding events
 * into xnap_ho_src_transition()/xnap_ho_tgt_transition() and executing the
 * returned action (send a message, mark/check a timer, ...). The transition
 * functions are pure: (state, event) -> (action, next_state); they never
 * allocate and have no side effects of their own.
 *
 * Two procedures, modeled as one linear state chain per role (TS 38.423 §8.4.1
 * Xn Setup feeds directly into the per-UE Handover Preparation states of
 * §8.2.1 once the association is up):
 *   1. Xn Setup   - one-time per-SCTP-association bring-up, not per-UE.
 *   2. Xn Handover - per-UE-association procedure, reuses the established
 *                    association.
 *
 * Source and target are separate state machines. They communicate only via
 * the Xn/NG/air messages below; neither side may reach into the other's
 * state directly.
 *
 * Interfaces (label kept explicit to avoid conflating message planes):
 *   Xn (source<->target): HANDOVER REQUEST, HANDOVER REQUEST ACKNOWLEDGE,
 *     HANDOVER PREPARATION FAILURE, SN STATUS TRANSFER, UE CONTEXT RELEASE,
 *     HANDOVER CANCEL, XN SETUP REQUEST/RESPONSE/FAILURE.
 *     Note: HANDOVER CANCEL is a Class 2 (no-response) procedure (§9.1.1.6) -
 *     there is no HANDOVER CANCEL ACKNOWLEDGE message in XnAP. The target's
 *     reaction is purely local (release the reserved context); it never
 *     replies.
 *   NG (target<->AMF): Path Switch Request / Acknowledge / Failure. This is an
 *     NGAP procedure outside XnAP; it has no XnAP timer of its own and none is
 *     modeled here (see xnap_ho_tgt_event_t).
 *   Air (UE<->target): RRC Reconfiguration Complete - arrives as an internal
 *     event at the target, never as an XnAP PDU.
 *
 * Timers - exactly two, both source-side (TS 38.423 §8.2.1.2). The target has
 * no XnAP handover timer at all: if RRC Reconfiguration Complete never
 * arrives, the target's reserved UE context is only freed when the SOURCE's
 * TXnRELOCoverall expires and sends HANDOVER CANCEL. Do not add a target
 * timer to "fix" this — it is the specified dependency, not a gap.
 *   TXnRELOCprep:    started when HANDOVER REQUEST is sent (-> HO_REQ_SENT).
 *                    Stopped by HANDOVER REQUEST ACKNOWLEDGE or HANDOVER
 *                    PREPARATION FAILURE. Expiry cancels the in-flight
 *                    preparation (send HANDOVER CANCEL).
 *   TXnRELOCoverall: started the instant TXnRELOCprep stops on a successful
 *                    Ack (immediate handover: the two never overlap - they
 *                    run strictly sequentially). Stopped by UE CONTEXT
 *                    RELEASE. Expiry means relocation failed: send HANDOVER
 *                    CANCEL and release the UE locally.
 *
 * The timer scaffolding below follows the same tick-counter + start-timestamp
 * convention used throughout this codebase for protocol timers (X2AP's
 * TX2RELOCprep/TX2RELOCoverall in openair2/X2AP/x2ap_timers.h /
 * x2ap_ids.h — the LTE analogs of these same two 38.423 timers; PDCP's
 * t_reordering/discard_timer and RLC's t_poll_retransmit/t_reassembly follow
 * the identical start-vs-current-tick comparison). No OS/ITTI timer objects
 * are created here.
 *
 * Not modeled: Conditional Handover (CHO). Everything here assumes immediate
 * handover; a CHO extension must live behind its own clearly separate branch.
 */

#ifndef XNAP_HO_SM_H_
#define XNAP_HO_SM_H_

#include <stdbool.h>
#include <stdint.h>

/* ======================================================================== */
/* Source role (the node the UE is leaving)                                 */
/* ======================================================================== */

typedef enum {
  XNAP_HO_SRC_SCTP_READY = 0,    /* SCTP association up; Xn Setup not yet started */
  XNAP_HO_SRC_XN_SETUP_REQ_SENT, /* XN SETUP REQUEST sent (TS 38.423 §8.4.1), awaiting response */
  XNAP_HO_SRC_XN_READY,          /* Xn Setup complete; no HO in progress for this UE */
  XNAP_HO_SRC_HO_REQ_SENT,       /* HANDOVER REQUEST sent (§9.1.1.1); TXnRELOCprep running */
  XNAP_HO_SRC_HO_PREPARED,       /* "Prepared Handover" per §8.2.1.2; TXnRELOCoverall running, awaiting UE CONTEXT RELEASE */
  XNAP_HO_SRC_HO_COMPLETE,       /* UE CONTEXT RELEASE received (§9.1.1.5); HO done, both timers stopped */
} xnap_ho_src_state_t;

typedef enum {
  XNAP_HO_SRC_EV_XN_SETUP_RESPONSE,         /* Xn: XN SETUP RESPONSE rx (§8.4.1) */
  XNAP_HO_SRC_EV_XN_SETUP_FAILURE,          /* Xn: XN SETUP FAILURE rx (§8.4.1) */
  XNAP_HO_SRC_EV_HO_TRIGGER,                /* internal: RRC/measurement decided to hand over this UE */
  XNAP_HO_SRC_EV_HANDOVER_REQUEST_ACK,      /* Xn: HANDOVER REQUEST ACKNOWLEDGE rx (§9.1.1.2) */
  XNAP_HO_SRC_EV_HANDOVER_PREP_FAILURE,     /* Xn: HANDOVER PREPARATION FAILURE rx (§9.1.1.3) */
  XNAP_HO_SRC_EV_UE_CONTEXT_RELEASE,        /* Xn: UE CONTEXT RELEASE rx (§9.1.1.5) */
  XNAP_HO_SRC_EV_TIMER_RELOCPREP_EXPIRY,    /* TXnRELOCprep expired */
  XNAP_HO_SRC_EV_TIMER_RELOCOVERALL_EXPIRY, /* TXnRELOCoverall expired */
} xnap_ho_src_event_t;

typedef enum {
  XNAP_HO_SRC_ACT_NONE = 0,
  XNAP_HO_SRC_ACT_SEND_XN_SETUP_REQUEST,   /* send Xn XN SETUP REQUEST */
  XNAP_HO_SRC_ACT_RETRY_XN_SETUP,          /* XN SETUP FAILURE rx; caller decides whether/when to retry */
  XNAP_HO_SRC_ACT_SEND_HANDOVER_REQUEST,   /* send Xn HANDOVER REQUEST; mark TXnRELOCprep start */
  XNAP_HO_SRC_ACT_SEND_SN_STATUS_TRANSFER, /* stop TXnRELOCprep, mark TXnRELOCoverall start, send Xn SN STATUS TRANSFER */
  XNAP_HO_SRC_ACT_TERMINATE_PREPARATION,   /* HO Prep Failure rx: stop TXnRELOCprep; no Prepared Handover exists, nothing to cancel */
  XNAP_HO_SRC_ACT_LOCAL_RELEASE,           /* UE Context Release rx: stop TXnRELOCoverall, release local HO state */
  XNAP_HO_SRC_ACT_SEND_HANDOVER_CANCEL,    /* TXnRELOCprep expiry: cancel the in-flight preparation (no ack expected, see header note) */
  XNAP_HO_SRC_ACT_CANCEL_AND_RELEASE,      /* TXnRELOCoverall expiry: relocation failed - send HANDOVER CANCEL and release the UE locally */
  XNAP_HO_SRC_ACT_ILLEGAL,                 /* event not valid in current state: logged, no effect */
} xnap_ho_src_action_t;

typedef struct {
  xnap_ho_src_state_t next_state;
  xnap_ho_src_action_t action;
} xnap_ho_src_result_t;

/* Pure transition function: does not touch timers or send anything itself -
 * the caller executes `action` (including the timer mark/stop it implies,
 * see the timer scaffolding below) and then stores `next_state`. */
xnap_ho_src_result_t xnap_ho_src_transition(xnap_ho_src_state_t state, xnap_ho_src_event_t event);

/* ======================================================================== */
/* Target role (the node the UE is entering)                                */
/* ======================================================================== */

typedef enum {
  XNAP_HO_TGT_SCTP_READY = 0,            /* SCTP association up; Xn Setup not yet started */
  XNAP_HO_TGT_XN_SETUP_PROCESSING,       /* XN SETUP REQUEST rx, validating locally before responding */
  XNAP_HO_TGT_XN_READY,                  /* Xn Setup complete; no HO in progress for this UE */
  XNAP_HO_TGT_HO_REQ_PROCESSING,         /* HANDOVER REQUEST rx, running admission control (§9.1.1.1).
                                           * Not a separately-named state in the source spec ladder (which
                                           * describes admission control inline) - added so this transition
                                           * function can stay a pure (state,event)->(action,next_state) map
                                           * instead of hiding an admission decision behind a stored callback;
                                           * mirrors XN_SETUP_PROCESSING above. */
  XNAP_HO_TGT_HO_REQ_ACK_SENT,           /* HANDOVER REQUEST ACKNOWLEDGE sent (§9.1.1.2); awaiting UE arrival over the air */
  XNAP_HO_TGT_UE_ARRIVED_PATH_SWITCHING, /* RRC Reconfiguration Complete rx; NG Path Switch Request sent, awaiting AMF */
  XNAP_HO_TGT_UE_CTXT_REL_SENT,          /* Xn UE CONTEXT RELEASE sent (§9.1.1.5) to source; HO done */
} xnap_ho_tgt_state_t;

typedef enum {
  XNAP_HO_TGT_EV_XN_SETUP_REQUEST,      /* Xn: XN SETUP REQUEST rx (§8.4.1) */
  XNAP_HO_TGT_EV_XN_SETUP_ACCEPTED,     /* local validation of the setup request completed successfully */
  XNAP_HO_TGT_EV_XN_SETUP_REJECTED,     /* local validation of the setup request failed */
  XNAP_HO_TGT_EV_HANDOVER_REQUEST,      /* Xn: HANDOVER REQUEST rx (§9.1.1.1) */
  XNAP_HO_TGT_EV_ADMISSION_ACCEPTED,    /* local admission control (bearers/resources) succeeded */
  XNAP_HO_TGT_EV_ADMISSION_REJECTED,    /* local admission control failed */
  XNAP_HO_TGT_EV_RRC_RECONFIG_COMPLETE, /* Air: RRC Reconfiguration Complete rx from the UE - NOT an Xn PDU */
  XNAP_HO_TGT_EV_PATH_SWITCH_SUCCESS,   /* NG: Path Switch Request Acknowledge rx from AMF */
  XNAP_HO_TGT_EV_PATH_SWITCH_FAILURE,   /* NG: Path Switch Request Failure rx from AMF */
  XNAP_HO_TGT_EV_HANDOVER_CANCEL,       /* Xn: HANDOVER CANCEL rx (§9.1.1.6, Class 2 - no reply sent) */
} xnap_ho_tgt_event_t;

typedef enum {
  XNAP_HO_TGT_ACT_NONE = 0,
  XNAP_HO_TGT_ACT_RUN_XN_SETUP_VALIDATION,           /* caller validates the setup request, then feeds back ACCEPTED/REJECTED */
  XNAP_HO_TGT_ACT_SEND_XN_SETUP_RESPONSE,            /* validation accepted: send Xn XN SETUP RESPONSE */
  XNAP_HO_TGT_ACT_SEND_XN_SETUP_FAILURE,             /* validation rejected: send Xn XN SETUP FAILURE */
  XNAP_HO_TGT_ACT_RUN_ADMISSION_CONTROL,             /* caller runs admission control, then feeds back ACCEPTED/REJECTED */
  XNAP_HO_TGT_ACT_SEND_HANDOVER_REQUEST_ACK,         /* admission accepted: send Xn HANDOVER REQUEST ACKNOWLEDGE */
  XNAP_HO_TGT_ACT_SEND_HANDOVER_PREP_FAILURE,        /* admission rejected: send Xn HANDOVER PREPARATION FAILURE; no reserved context survives to cancel */
  XNAP_HO_TGT_ACT_SEND_PATH_SWITCH_REQUEST,          /* UE arrived over the air: send NG Path Switch Request to the AMF */
  XNAP_HO_TGT_ACT_SEND_UE_CONTEXT_RELEASE,           /* Path Switch succeeded: send Xn UE CONTEXT RELEASE to source */
  XNAP_HO_TGT_ACT_LOCAL_RELEASE_PATH_SWITCH_FAILURE, /* Path Switch failed: release locally. No XnAP message exists for
                                                       * this outcome - the source's TXnRELOCoverall expiry is what
                                                       * eventually notices and sends HANDOVER CANCEL (see header note).
                                                       * // VERIFY vs 38.423: spec does not define target behaviour on
                                                       * NG Path Switch failure; this is the conservative reading. */
  XNAP_HO_TGT_ACT_RELEASE_RESERVED_CONTEXT,          /* HANDOVER CANCEL rx: release the reserved UE context locally (no reply, Class 2 procedure) */
  XNAP_HO_TGT_ACT_ILLEGAL,                           /* event not valid in current state: logged, no effect */
} xnap_ho_tgt_action_t;

typedef struct {
  xnap_ho_tgt_state_t next_state;
  xnap_ho_tgt_action_t action;
} xnap_ho_tgt_result_t;

/* Pure transition function, same contract as xnap_ho_src_transition(). Both
 * "admission control" and "Xn Setup validation" are modeled as two-step
 * events (REQUEST -> ACT_RUN_*, then the caller feeds back
 * ACCEPTED/REJECTED) rather than a callback stored in this module, so the
 * core stays a plain function with no hidden state and no assumption about
 * whether the caller's check is synchronous or async. */
xnap_ho_tgt_result_t xnap_ho_tgt_transition(xnap_ho_tgt_state_t state, xnap_ho_tgt_event_t event);

/* ======================================================================== */
/* Timer scaffolding (source-only: TXnRELOCprep / TXnRELOCoverall)          */
/* ======================================================================== */

/* Shared per-Xn-instance tick counter + configured durations, mirroring
 * x2ap_timers_t (openair2/X2AP/x2ap_timers.h). The caller increments `tti`
 * once per periodic tick (whatever cadence it already runs — once per TTI,
 * once per ms, ...); nothing here starts a real OS/ITTI timer. */
typedef struct {
  uint64_t tti;           /* incremented by the caller once per tick */
  int t_xn_reloc_prep;    /* TXnRELOCprep duration, in tick units */
  int t_xn_reloc_overall; /* TXnRELOCoverall duration, in tick units */
} xnap_ho_src_timers_t;

void xnap_ho_src_timers_init(xnap_ho_src_timers_t *t, int t_xn_reloc_prep, int t_xn_reloc_overall);

/* Per-UE timer start marks, mirroring x2ap_id's t_reloc_prep_start /
 * tx2_reloc_overall_start. Which mark is meaningful is implied by
 * xnap_ho_src_state_t (HO_REQ_SENT -> prep, HO_PREPARED -> overall) exactly
 * as X2AP keys off x2id_state_t rather than storing a separate "which timer"
 * field — the two never run concurrently so there is never ambiguity. */
typedef struct {
  uint64_t t_xn_reloc_prep_start;
  uint64_t t_xn_reloc_overall_start;
} xnap_ho_src_timer_marks_t;

void xnap_ho_src_set_relocprep_start(xnap_ho_src_timer_marks_t *m, uint64_t now);
void xnap_ho_src_set_relocoverall_start(xnap_ho_src_timer_marks_t *m, uint64_t now);

/* Polled once per tick per UE — same shape as the inner-loop body of X2AP's
 * x2ap_check_timers(), minus the ASN.1/ITTI dispatch (that stays the
 * caller's job so this module has no XNAP-encode/ITTI dependency). Returns
 * true and fills *expired when the timer implied by `state` has crossed its
 * configured duration; the caller then feeds *expired into
 * xnap_ho_src_transition(). */
bool xnap_ho_src_timer_check(xnap_ho_src_state_t state,
                              const xnap_ho_src_timer_marks_t *marks,
                              const xnap_ho_src_timers_t *timers,
                              xnap_ho_src_event_t *expired);

#endif /* XNAP_HO_SM_H_ */
