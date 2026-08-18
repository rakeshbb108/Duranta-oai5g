/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* Periodic tick + expiry dispatch for the source-side TXnRELOCprep/
 * TXnRELOCoverall guard timers (xnap_ho_sm.h). Mirrors x2ap_timers.h/.c
 * (openair2/X2AP) — same "one shared tick, per-UE start marks" model, adapted
 * to XNAP's hashtable-based UE storage via the bounded roster in xnap_ids.h. */

#ifndef XNAP_HO_TIMERS_H_
#define XNAP_HO_TIMERS_H_

#include <stdint.h>
#include "common/platform_types.h"

/* One tick == one millisecond of the shared common/utils/time_manager clock
 * (real or simulated, see xnap_ms_tick() in xnap_gNB.c) — same resolution as
 * PDCP's/RLC's/X2AP's own timers, which run off that same clock. */
#define XNAP_HO_TIMER_TICK_MS 1

/* Call once, when the local gNB's XnAP setup info/config becomes known
 * (xnap_gNB_handle_register_gnb). Durations in milliseconds. */
void xnap_ho_timers_init(uint32_t t_xn_reloc_prep_ms, uint32_t t_xn_reloc_overall_ms);

/* Current shared tick (ms), for marking a timer start (xnap_ids.h's
 * xnap_set_ue_timer_mark_relocprep()/_relocoverall()). */
uint64_t xnap_ho_timers_now(void);

/* Call on every XNAP_HO_TIMER_TICK (see xnap_gNB.c): advances the shared
 * tick and, for every tracked source UE whose timer has crossed its
 * duration, sends HandoverCancel and notifies RRC for local cleanup. */
void xnap_check_ho_timers(instance_t instance);

#endif /* XNAP_HO_TIMERS_H_ */
