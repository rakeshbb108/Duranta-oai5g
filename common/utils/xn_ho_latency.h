/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* Xn Handover latency instrumentation: per-HO event timestamps (T0-T7, per
 * the source/target signalling steps of 3GPP TS 38.423 Xn HO), appended as
 * CSV rows for offline aggregation into paper-ready latency statistics.
 * Source, target, and (in a split deployment) the target's CU-UP are
 * normally separate processes/hosts, so each one appends its own local CSV;
 * ci-scripts/xn_ho/xn_ho_csv_merge.py joins source+target on
 * (source_gnb_id, s_xnap_id) -- the XnAP UE ID already carried in every
 * message of the procedure -- and joins in the CU-UP's interruption/loss
 * data on rrc_ue_id, into one row per handover. */

#ifndef COMMON_UTILS_XN_HO_LATENCY_H_
#define COMMON_UTILS_XN_HO_LATENCY_H_

#include <stdint.h>
#include <stdbool.h>
#include "common/platform_constants.h"

/* A single event mark: both clocks are recorded because Xn Prep (T2-T1) and
 * Path-Switch (T6-T5) are single-process intervals where CLOCK_MONOTONIC is
 * exact, while Radio Exec (T4-T3) and cross-host totals need CLOCK_REALTIME
 * on NTP/PTP-synced hosts -- same constraint documented for this project's
 * existing wall_clock log-based tooling. */
typedef struct {
  uint64_t mono_ns;
  uint64_t wall_ns;
  bool set;
} xn_ho_ts_t;

void xn_ho_ts_mark(xn_ho_ts_t *ts);

/* Delta in milliseconds between two marks made by the SAME process (uses
 * CLOCK_MONOTONIC, exact regardless of wall-clock sync) -- e.g. Xn Prep
 * (T1->T2) or Path-Switch (T5->T6). Returns -1.0 if either mark was never
 * set (e.g. the handover failed before reaching it). NOT valid across two
 * different processes/hosts -- see common/utils/xn_ho_latency.h's own
 * module comment and ci-scripts/xn_ho/xn_ho_csv_merge.py for that case. */
double xn_ho_delta_ms(xn_ho_ts_t start, xn_ho_ts_t end);

typedef enum {
  XN_HO_OUTCOME_SUCCESS,
  XN_HO_OUTCOME_PREP_FAILURE,
  XN_HO_OUTCOME_CANCELLED,
  XN_HO_OUTCOME_RELOCPREP_TIMEOUT,
  XN_HO_OUTCOME_RELOCOVERALL_TIMEOUT,
  XN_HO_OUTCOME_TARGET_ABORT,
} xn_ho_outcome_t;

const char *xn_ho_outcome_str(xn_ho_outcome_t o);

/* Source-side row: T0 (trigger), T1 (Handover Request sent), T2 (Handover
 * Request Ack received), T3 (RRC Reconfig/HO command sent to UE), T7 (UE
 * Context Release received). Per-DRB dl_count_sn is the SN Status Transfer
 * boundary (highest-assigned DL PDCP COUNT), used downstream to estimate
 * loss against the target's first-delivered SN. */
typedef struct {
  uint32_t source_gnb_id;
  uint32_t s_xnap_id;
  uint32_t t_xnap_id;
  uint32_t rrc_ue_id;
  uint32_t neighbour_pci;
  xn_ho_ts_t t0, t1, t2, t3, t7;
  int n_drb;
  int drb_ids[MAX_DRBS_PER_UE];
  uint32_t dl_count_sn[MAX_DRBS_PER_UE];
  xn_ho_outcome_t outcome;
} xn_ho_source_record_t;

/* Target-side row: T4 (RA + Reconfig Complete received), T5 (Path Switch
 * Request sent), T6 (Path Switch Request Ack received), T7 (UE Context
 * Release sent). */
typedef struct {
  uint32_t target_gnb_id;
  uint32_t s_xnap_id;
  uint32_t t_xnap_id;
  uint32_t rrc_ue_id;
  xn_ho_ts_t t4, t5, t6, t7;
  xn_ho_outcome_t outcome;
} xn_ho_target_record_t;

/* CU-UP-side row: the first DL PDCP PDU actually handed to RLC for
 * (rrc_ue_id, drb_id) after (re)activation -- the practical end of the
 * user-plane interruption window. Written directly from the CU-UP process
 * (common/utils/xn_ho_latency.h has no access to the target's XnAP ids, but
 * CU-UP's own ue_id is always identical to the target's rrc_ue_id -- CU-CP
 * sets gNB_cu_cp_ue_id = UE->rrc_ue_id and CU-UP mirrors it verbatim as its
 * own gNB_cu_up_ue_id -- so joining on rrc_ue_id alone is sufficient; see
 * ci-scripts/xn_ho/xn_ho_csv_merge.py). In a monolithic gNB this is just a
 * third file on the same host as the source/target CSVs. */
typedef struct {
  uint32_t rrc_ue_id;
  int drb_id;
  uint32_t sn;
  xn_ho_ts_t first_tx;
} xn_ho_cuup_first_tx_record_t;

/* CSV path defaults to "./xn_ho_latency_{source,target,cuup}.csv" in the
 * process's working directory; override with the XN_HO_LATENCY_CSV_DIR
 * environment variable (checked once, lazily, on first append). Thread-safe:
 * one mutex per file, held only for the append itself. */
void xn_ho_latency_append_source(const xn_ho_source_record_t *rec);
void xn_ho_latency_append_target(const xn_ho_target_record_t *rec);
void xn_ho_latency_append_cuup_first_tx(const xn_ho_cuup_first_tx_record_t *rec);

#endif /* COMMON_UTILS_XN_HO_LATENCY_H_ */
