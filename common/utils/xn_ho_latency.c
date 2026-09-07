/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "xn_ho_latency.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

void xn_ho_ts_mark(xn_ho_ts_t *ts)
{
  struct timespec mono, wall;
  clock_gettime(CLOCK_MONOTONIC, &mono);
  clock_gettime(CLOCK_REALTIME, &wall);
  ts->mono_ns = (uint64_t) mono.tv_sec * 1000000000ULL + mono.tv_nsec;
  ts->wall_ns = (uint64_t) wall.tv_sec * 1000000000ULL + wall.tv_nsec;
  ts->set = true;
}

const char *xn_ho_outcome_str(xn_ho_outcome_t o)
{
  switch (o) {
    case XN_HO_OUTCOME_SUCCESS: return "SUCCESS";
    case XN_HO_OUTCOME_PREP_FAILURE: return "PREP_FAILURE";
    case XN_HO_OUTCOME_CANCELLED: return "CANCELLED";
    case XN_HO_OUTCOME_RELOCPREP_TIMEOUT: return "RELOCPREP_TIMEOUT";
    case XN_HO_OUTCOME_RELOCOVERALL_TIMEOUT: return "RELOCOVERALL_TIMEOUT";
    case XN_HO_OUTCOME_TARGET_ABORT: return "TARGET_ABORT";
    default: return "UNKNOWN";
  }
}

static const char *csv_dir(void)
{
  const char *d = getenv("XN_HO_LATENCY_CSV_DIR");
  return d ? d : ".";
}

/* One mutex per file: appends from the RRC task thread are already
 * serialised in practice (single ITTI task per process), but the mutex
 * makes that an explicit guarantee rather than an assumption. The CU-UP
 * first-tx capture runs on the PDCP data path, which is not necessarily
 * single-threaded, so its lock is load-bearing rather than just defensive. */
static pthread_mutex_t source_csv_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t target_csv_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t cuup_csv_lock = PTHREAD_MUTEX_INITIALIZER;

static FILE *open_csv_append(const char *name, const char *header)
{
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s", csv_dir(), name);
  bool exists = (access(path, F_OK) == 0);
  FILE *f = fopen(path, "a");
  if (f == NULL)
    return NULL;
  if (!exists)
    fprintf(f, "%s\n", header);
  return f;
}

/* format a per-DRB list column as "id:value;id:value;..." (empty if n==0) */
static void fmt_drb_u32(char *out, size_t out_len, int n, const int *drb_ids, const uint32_t *values)
{
  size_t off = 0;
  out[0] = '\0';
  for (int i = 0; i < n && off < out_len; i++) {
    int written = snprintf(out + off, out_len - off, "%s%d:%u", i ? ";" : "", drb_ids[i], values[i]);
    if (written < 0)
      break;
    off += (size_t) written;
  }
}

void xn_ho_latency_append_source(const xn_ho_source_record_t *rec)
{
  char dl_count_col[512];
  fmt_drb_u32(dl_count_col, sizeof(dl_count_col), rec->n_drb, rec->drb_ids, rec->dl_count_sn);

  pthread_mutex_lock(&source_csv_lock);
  FILE *f = open_csv_append("xn_ho_latency_source.csv",
                            "source_gnb_id,s_xnap_id,t_xnap_id,rrc_ue_id,neighbour_pci,"
                            "t0_mono_ns,t0_wall_ns,t1_mono_ns,t1_wall_ns,t2_mono_ns,t2_wall_ns,"
                            "t3_mono_ns,t3_wall_ns,t7_mono_ns,t7_wall_ns,dl_count_sn,outcome");
  if (f != NULL) {
    fprintf(f,
            "%u,%u,%u,%u,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%s,%s\n",
            rec->source_gnb_id, rec->s_xnap_id, rec->t_xnap_id, rec->rrc_ue_id, rec->neighbour_pci,
            (unsigned long) rec->t0.mono_ns, (unsigned long) rec->t0.wall_ns,
            (unsigned long) rec->t1.mono_ns, (unsigned long) rec->t1.wall_ns,
            (unsigned long) rec->t2.mono_ns, (unsigned long) rec->t2.wall_ns,
            (unsigned long) rec->t3.mono_ns, (unsigned long) rec->t3.wall_ns,
            (unsigned long) rec->t7.mono_ns, (unsigned long) rec->t7.wall_ns,
            dl_count_col, xn_ho_outcome_str(rec->outcome));
    fclose(f);
  }
  pthread_mutex_unlock(&source_csv_lock);
}

void xn_ho_latency_append_target(const xn_ho_target_record_t *rec)
{
  pthread_mutex_lock(&target_csv_lock);
  FILE *f = open_csv_append("xn_ho_latency_target.csv",
                            "target_gnb_id,s_xnap_id,t_xnap_id,rrc_ue_id,"
                            "t4_mono_ns,t4_wall_ns,t5_mono_ns,t5_wall_ns,t6_mono_ns,t6_wall_ns,"
                            "t7_mono_ns,t7_wall_ns,outcome");
  if (f != NULL) {
    fprintf(f,
            "%u,%u,%u,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%s\n",
            rec->target_gnb_id, rec->s_xnap_id, rec->t_xnap_id, rec->rrc_ue_id,
            (unsigned long) rec->t4.mono_ns, (unsigned long) rec->t4.wall_ns,
            (unsigned long) rec->t5.mono_ns, (unsigned long) rec->t5.wall_ns,
            (unsigned long) rec->t6.mono_ns, (unsigned long) rec->t6.wall_ns,
            (unsigned long) rec->t7.mono_ns, (unsigned long) rec->t7.wall_ns,
            xn_ho_outcome_str(rec->outcome));
    fclose(f);
  }
  pthread_mutex_unlock(&target_csv_lock);
}

void xn_ho_latency_append_cuup_first_tx(const xn_ho_cuup_first_tx_record_t *rec)
{
  pthread_mutex_lock(&cuup_csv_lock);
  FILE *f = open_csv_append("xn_ho_latency_cuup.csv", "rrc_ue_id,drb_id,sn,mono_ns,wall_ns");
  if (f != NULL) {
    fprintf(f,
            "%u,%d,%u,%lu,%lu\n",
            rec->rrc_ue_id, rec->drb_id, rec->sn,
            (unsigned long) rec->first_tx.mono_ns, (unsigned long) rec->first_tx.wall_ns);
    fclose(f);
  }
  pthread_mutex_unlock(&cuup_csv_lock);
}
